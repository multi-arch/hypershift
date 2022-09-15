package azure

import (
	"context"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/go-logr/logr"
	"github.com/spf13/cobra"

	apifixtures "github.com/openshift/hypershift/api/fixtures"
	"github.com/openshift/hypershift/cmd/log"
	"github.com/openshift/hypershift/support/releaseinfo/registryclient"
	utilrand "k8s.io/apimachinery/pkg/util/rand"
	utilpointer "k8s.io/utils/pointer"
	"sigs.k8s.io/yaml"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/compute/armcompute"
	"github.com/Azure/azure-sdk-for-go/services/compute/mgmt/2021-12-01/compute"
	"github.com/Azure/azure-sdk-for-go/services/dns/mgmt/2018-05-01/dns"
	"github.com/Azure/azure-sdk-for-go/services/msi/mgmt/2018-11-30/msi"
	"github.com/Azure/azure-sdk-for-go/services/network/mgmt/2021-05-01/network"
	"github.com/Azure/azure-sdk-for-go/services/preview/authorization/mgmt/2020-04-01-preview/authorization"

	"github.com/Azure/azure-sdk-for-go/services/privatedns/mgmt/2018-09-01/privatedns"
	"github.com/Azure/azure-sdk-for-go/services/resources/mgmt/2020-10-01/resources"
	"github.com/Azure/azure-sdk-for-go/services/storage/mgmt/2021-04-01/storage"
	"github.com/Azure/go-autorest/autorest"
	"github.com/Azure/go-autorest/autorest/azure"
	"github.com/Azure/go-autorest/autorest/azure/auth"
	"github.com/hashicorp/go-uuid"

	// This is the same client as terraform uses: https://github.com/hashicorp/terraform-provider-azurerm/blob/b0c897055329438be6a3a159f6ffac4e1ce958f2/internal/services/storage/blobs.go#L17
	// The one from the azure sdk is cumbersome to use (distinct authorizer, requires to manually construct the full target url), and only allows upload from url for files that are not bigger than 256M.
	"github.com/tombuildsstuff/giovanni/storage/2019-12-12/blob/blobs"
)

const (
	DiskName              = "HyperShiftImageGalleryDisk"
	ArchitectureAMD64     = "amd64"
	ArchitectureS390X     = "s390x"
	ArchitecturePPC64LE   = "ppc64le"
	ArchitectureARM64     = "arm64"
	Arm64GalleryImageName = "RHCOS_Arm64"
	Amd64GalleryImageName = "RHCOS_Amd64"
)

type CreateInfraOptions struct {
	Name            string
	BaseDomain      string
	Location        string
	InfraID         string
	CredentialsFile string
	Credentials     *apifixtures.AzureCreds
	OutputFile      string
	PullSecret      string
	ReleaseImage    string
}

type GalleryImageDefinitionOptions struct {
	Context             context.Context
	Location            string
	ResourceGroupName   string
	ImageGalleryName    string
	SubscriptionID      string
	ImageDefinitionName string
	Arch                string
	BootImageID         string
	AzureCreds          azcore.TokenCredential
}

func NewCreateCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:          "azure",
		Short:        "Creates Azure infrastructure resources for a cluster",
		SilenceUsage: true,
	}

	opts := CreateInfraOptions{
		Location: "eastus",
	}

	cmd.Flags().StringVar(&opts.InfraID, "infra-id", opts.InfraID, "Cluster ID(required)")
	cmd.Flags().StringVar(&opts.CredentialsFile, "azure-creds", opts.CredentialsFile, "Path to a credentials file (required)")
	cmd.Flags().StringVar(&opts.Location, "location", opts.Location, "Location where cluster infra should be created")
	cmd.Flags().StringVar(&opts.BaseDomain, "base-domain", opts.BaseDomain, "The ingress base domain for the cluster")
	cmd.Flags().StringVar(&opts.Name, "name", opts.Name, "A name for the cluster")
	cmd.Flags().StringVar(&opts.OutputFile, "output-file", opts.OutputFile, "Path to file that will contain output information from infra resources (optional)")

	cmd.MarkFlagRequired("infra-id")
	cmd.MarkFlagRequired("azure-creds")
	cmd.MarkFlagRequired("name")

	l := log.Log
	cmd.RunE = func(cmd *cobra.Command, args []string) error {
		if _, err := opts.Run(cmd.Context(), l); err != nil {
			l.Error(err, "Failed to create infrastructure")
			return err
		}
		l.Info("Successfully created infrastructure")
		return nil
	}

	return cmd
}

func readCredentials(path string) (*apifixtures.AzureCreds, error) {
	raw, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read from %s: %w", path, err)
	}

	var result apifixtures.AzureCreds
	if err := yaml.Unmarshal(raw, &result); err != nil {
		return nil, fmt.Errorf("failed to unmarshal credentials: %w", err)
	}

	return &result, nil
}

type CreateInfraOutput struct {
	BaseDomain        string `json:"baseDomain"`
	PublicZoneID      string `json:"publicZoneID"`
	PrivateZoneID     string `json:"privateZoneID"`
	Location          string `json:"region"`
	ResourceGroupName string `json:"resourceGroupName"`
	VNetID            string `json:"vnetID"`
	VnetName          string `json:"vnetName"`
	SubnetName        string `json:"subnetName"`
	BootImageID       string `json:"bootImageID"`
	InfraID           string `json:"infraID"`
	MachineIdentityID string `json:"machineIdentityID"`
	SecurityGroupName string `json:"securityGroupName"`
}

func resourceGroupName(clusterName, infraID string) string {
	return clusterName + "-" + infraID
}

func (o *CreateInfraOptions) Run(ctx context.Context, l logr.Logger) (*CreateInfraOutput, error) {
	creds := o.Credentials
	if creds == nil {
		var err error
		creds, err = readCredentials(o.CredentialsFile)
		if err != nil {
			return nil, fmt.Errorf("failed to read the credentials: %w", err)
		}
		os.Setenv("AZURE_TENANT_ID", creds.TenantID)
		os.Setenv("AZURE_CLIENT_ID", creds.ClientID)
		os.Setenv("AZURE_CLIENT_SECRET", creds.ClientSecret)
		l.Info("Using credentials from file", "path", o.CredentialsFile)
	}

	authorizer, err := auth.ClientCredentialsConfig{
		TenantID:     creds.TenantID,
		ClientID:     creds.ClientID,
		ClientSecret: creds.ClientSecret,
		AADEndpoint:  azure.PublicCloud.ActiveDirectoryEndpoint,
		Resource:     azure.PublicCloud.ResourceManagerEndpoint,
	}.Authorizer()
	if err != nil {
		return nil, fmt.Errorf("failed to get azure authorizer: %w", err)
	}

	result := CreateInfraOutput{
		Location:   o.Location,
		InfraID:    o.InfraID,
		BaseDomain: o.BaseDomain,
	}

	zonesClient := dns.NewZonesClient(creds.SubscriptionID)
	zonesClient.Authorizer = authorizer
	dnsZone, err := findDNSZone(ctx, zonesClient, o.BaseDomain)
	if err != nil {
		return nil, fmt.Errorf("failed to find dns zone %s: %w", o.BaseDomain, err)
	}
	result.PublicZoneID = *dnsZone.ID

	resourceGroupClient := resources.NewGroupsClient(creds.SubscriptionID)
	resourceGroupClient.Authorizer = authorizer

	resourceGroupName := resourceGroupName(o.Name, o.InfraID)
	rg, err := resourceGroupClient.CreateOrUpdate(ctx, resourceGroupName, resources.Group{Location: utilpointer.String(o.Location)})
	if err != nil {
		return nil, fmt.Errorf("failed to create resource group: %w", err)
	}
	result.ResourceGroupName = *rg.Name
	l.Info("Successfuly created resourceGroup", "name", *rg.Name)

	identityClient := msi.NewUserAssignedIdentitiesClient(creds.SubscriptionID)
	identityClient.Authorizer = authorizer

	identity, err := identityClient.CreateOrUpdate(ctx, resourceGroupName, o.Name+"-"+o.InfraID, msi.Identity{Location: &o.Location})
	if err != nil {
		return nil, fmt.Errorf("failed to create managed identity: %w", err)
	}
	result.MachineIdentityID = *identity.ID

	roleDefinitionClient := authorization.NewRoleDefinitionsClient(creds.SubscriptionID)
	roleDefinitionClient.Authorizer = authorizer
	roleDefinitions, err := roleDefinitionClient.List(ctx, *rg.ID, "roleName eq 'Contributor'")
	if err != nil {
		return nil, fmt.Errorf("failed to list roleDefinitions: %w", err)
	}
	if len(roleDefinitions.Values()) != 1 {
		return nil, fmt.Errorf("didn't get exactly one roledefinition back: %+v", roleDefinitions.Values())
	}

	roleAssignmentClient := authorization.NewRoleAssignmentsClient(creds.SubscriptionID)
	roleAssignmentClient.Authorizer = authorizer

	roleAssignmentName, err := uuid.GenerateUUID()
	if err != nil {
		return nil, fmt.Errorf("failed to generate uuid for role assignment name: %w", err)
	}

	l.Info("Assigning role to managed identity, this may take some time")
	for try := 0; try < 100; try++ {
		_, err := roleAssignmentClient.Create(ctx, *rg.ID, roleAssignmentName, authorization.RoleAssignmentCreateParameters{RoleAssignmentProperties: &authorization.RoleAssignmentProperties{
			RoleDefinitionID: roleDefinitions.Values()[0].ID,
			PrincipalID:      utilpointer.String(identity.PrincipalID.String()),
		}})
		if err != nil {
			if try < 99 {
				time.Sleep(time.Second)
				continue
			}
			return nil, fmt.Errorf("failed to add role assignment to role: %w", err)
		}
		break
	}

	securityGroupClient := network.NewSecurityGroupsClient(creds.SubscriptionID)
	securityGroupClient.Authorizer = authorizer

	l.Info("Creating network security group")
	securityGroupFuture, err := securityGroupClient.CreateOrUpdate(ctx, resourceGroupName, o.Name+"-"+o.InfraID+"-nsg", network.SecurityGroup{Location: &o.Location})
	if err != nil {
		return nil, fmt.Errorf("failed to create network security group: %w", err)
	}
	if err := securityGroupFuture.WaitForCompletionRef(ctx, securityGroupClient.Client); err != nil {
		return nil, fmt.Errorf("failed waiting for network security group creation to finish: %w", err)
	}
	securityGroup, err := securityGroupFuture.Result(securityGroupClient)
	if err != nil {
		return nil, fmt.Errorf("failed to get network security group creation result: %w", err)
	}
	result.SecurityGroupName = *securityGroup.Name
	l.Info("Created network security group")

	networksClient := network.NewVirtualNetworksClient(creds.SubscriptionID)
	networksClient.Authorizer = authorizer

	vnetFuture, err := networksClient.CreateOrUpdate(ctx, resourceGroupName, o.Name+"-"+o.InfraID, network.VirtualNetwork{
		Location: &o.Location,
		VirtualNetworkPropertiesFormat: &network.VirtualNetworkPropertiesFormat{
			AddressSpace: &network.AddressSpace{
				AddressPrefixes: &[]string{"10.0.0.0/16"},
			},
			Subnets: &[]network.Subnet{{
				Name: utilpointer.String("default"),
				SubnetPropertiesFormat: &network.SubnetPropertiesFormat{
					AddressPrefix:        utilpointer.String("10.0.0.0/24"),
					NetworkSecurityGroup: &network.SecurityGroup{ID: securityGroup.ID},
				},
			}},
		},
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create vnet: %w", err)
	}
	if err := vnetFuture.WaitForCompletionRef(ctx, networksClient.Client); err != nil {
		return nil, fmt.Errorf("failed to wait for vnet creation: %w", err)
	}
	vnet, err := vnetFuture.Result(networksClient)
	if err != nil {
		return nil, fmt.Errorf("failed to get vnet creation result: %w", err)
	}
	if vnet.Subnets == nil || len(*vnet.Subnets) < 1 {
		return nil, fmt.Errorf("created vnet has no subnets: %+v", vnet)
	}
	result.SubnetName = *(*vnet.Subnets)[0].Name
	result.VNetID = *vnet.ID
	result.VnetName = *vnet.Name
	l.Info("Successfully created vnet", "name", *vnet.Name, "id", *vnet.ID)

	privateZoneClient := privatedns.NewPrivateZonesClient(creds.SubscriptionID)
	privateZoneClient.Authorizer = authorizer

	privateZoneParams := privatedns.PrivateZone{
		Location: utilpointer.String("global"),
	}
	privateDNSZonePromise, err := privateZoneClient.CreateOrUpdate(ctx, *rg.Name, o.Name+"-azurecluster."+o.BaseDomain, privateZoneParams, "", "")
	if err != nil {
		return nil, fmt.Errorf("failed to create private DNS zone: %w", err)
	}
	if err := privateDNSZonePromise.WaitForCompletionRef(ctx, privateZoneClient.Client); err != nil {
		return nil, fmt.Errorf("failed waiting for private DNS zone completion: %w", err)
	}
	privateDNSZone, err := privateDNSZonePromise.Result(privateZoneClient)
	if err != nil {
		return nil, fmt.Errorf("failed to get result of private dns zone creation: %w", err)
	}
	result.PrivateZoneID = *privateDNSZone.ID
	l.Info("Successfuly created private DNS zone")

	privateZoneLinkClient := privatedns.NewVirtualNetworkLinksClient(creds.SubscriptionID)
	privateZoneLinkClient.Authorizer = authorizer

	virtualNetworkLinkParams := privatedns.VirtualNetworkLink{
		Location: utilpointer.String("global"),
		VirtualNetworkLinkProperties: &privatedns.VirtualNetworkLinkProperties{
			VirtualNetwork:      &privatedns.SubResource{ID: vnet.ID},
			RegistrationEnabled: utilpointer.BoolPtr(false),
		},
	}
	networkLinkPromise, err := privateZoneLinkClient.CreateOrUpdate(ctx, *rg.Name, *privateDNSZone.Name, o.Name+"-"+o.InfraID, virtualNetworkLinkParams, "", "")
	if err != nil {
		return nil, fmt.Errorf("failed to set up network link for private DNS zone: %w", err)
	}
	if err := networkLinkPromise.WaitForCompletionRef(ctx, privateZoneClient.Client); err != nil {
		return nil, fmt.Errorf("failed waiting for network link for private DNS zone: %w", err)
	}
	l.Info("Successfuly created private DNS zone link")

	azureCreds, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create Azure credentials to create image gallery: %w", err)
	}

	disk, err := createDisk(ctx, resourceGroupName, creds.SubscriptionID, o.Location, azureCreds)
	if err != nil {
		return nil, fmt.Errorf("failed to create disk for image gallery: %w", err)
	}

	// Create a image gallery with a unique identifier since Azure only allows one named image gallery instance type per subscription rather than per resource group
	var imageGalleryName string
	splitInfra := strings.Split(o.InfraID, "-")

	if len(splitInfra) <= 0 {
		return nil, fmt.Errorf("failed to parse infraID to generate unique identifier for : %s", o.InfraID)
	} else {
		imageGalleryName = "BootImageGallery_" + splitInfra[len(splitInfra)-1]
	}

	gallery, err := createGallery(ctx, resourceGroupName, imageGalleryName, creds.SubscriptionID, o.Location, azureCreds, *disk.ID)
	if err != nil {
		return nil, fmt.Errorf("failed to create image gallery: %w", err)
	}
	l.Info("Successfully created image gallery: " + *gallery.ID)

	// Create RHCOS Image Containers
	pullSecret, err := ioutil.ReadFile(o.PullSecret)
	if err != nil {
		return nil, fmt.Errorf("failed to read pull secret file: %w", err)
	}

	isManifestListImage, err := registryclient.IsMultiArchManifestList(ctx, o.ReleaseImage, pullSecret)
	if err != nil {
		return nil, fmt.Errorf("failed to determine if image is manifest listed: %w", err)
	}

	imageDefinitionOptions := &GalleryImageDefinitionOptions{
		Context:           ctx,
		Location:          o.Location,
		ResourceGroupName: resourceGroupName,
		ImageGalleryName:  imageGalleryName,
		SubscriptionID:    creds.SubscriptionID,
		AzureCreds:        azureCreds,
	}

	if isManifestListImage {
		// Verify manifest image contains current hosted architecture
		// Right now, we only care about adding in an ARM VHD; s390/ppc won't exist in azure for a while
		os := runtime.GOOS

		_, err = registryclient.FindArchManifest(ctx, o.ReleaseImage, pullSecret, os, ArchitectureARM64)
		if err != nil {
			return nil, fmt.Errorf("failed to find current os/arch to pull rhcos image - os: %s, arch: %s", os, ArchitectureARM64)
		}

		result.BootImageID, err = createRHCOSImageContainer(ctx, creds, authorizer, rg, resourceGroupName, o.Location, ArchitectureARM64)
		if err != nil {
			return nil, fmt.Errorf("failed to create RHCOS ARM image container: %w", err)
		}

		imageDefinitionOptions.Arch = ArchitectureARM64
		imageDefinitionOptions.BootImageID = result.BootImageID
		imageDefinitionOptions.ImageDefinitionName = Arm64GalleryImageName

		imageDefinitionID, err := createGalleryImageDefinition(imageDefinitionOptions)
		if err != nil {
			return nil, fmt.Errorf("failed to create image definition for %s: %w", imageDefinitionOptions.ImageDefinitionName, err)
		}
		l.Info("Successfully created image definition for " + imageDefinitionOptions.ImageDefinitionName + ", ID: " + imageDefinitionID)

		l.Info("Creating image definition version for " + imageDefinitionOptions.ImageDefinitionName)
		imageGalleryVersionID, err := createGalleryImageDefinitionVersion(imageDefinitionOptions)
		if err != nil {
			return nil, fmt.Errorf("failed to create image definition version for %s: %w", imageDefinitionOptions.ImageDefinitionName, err)
		}

		l.Info("Successfully created image version for " + imageDefinitionOptions.ImageDefinitionName + ", ID: " + imageGalleryVersionID)
	}

	result.BootImageID, err = createRHCOSImageContainer(ctx, creds, authorizer, rg, resourceGroupName, o.Location, ArchitectureAMD64)
	if err != nil {
		return nil, fmt.Errorf("failed to create x86 RHCOS image container: %w", err)
	}

	imageDefinitionOptions.Arch = ArchitectureAMD64
	imageDefinitionOptions.BootImageID = result.BootImageID
	imageDefinitionOptions.ImageDefinitionName = Amd64GalleryImageName

	imageDefinitionID, err := createGalleryImageDefinition(imageDefinitionOptions)
	if err != nil {
		return nil, fmt.Errorf("failed to create image definition for %s: %w", imageDefinitionOptions.ImageDefinitionName, err)
	}
	l.Info("Successfully created image definition for " + imageDefinitionOptions.ImageDefinitionName + ", ID: " + imageDefinitionID)

	l.Info("Creating image definition version for " + imageDefinitionOptions.ImageDefinitionName)
	imageGalleryVersionID, err := createGalleryImageDefinitionVersion(imageDefinitionOptions)
	if err != nil {
		return nil, fmt.Errorf("failed to create image definition version for %s: %w", imageDefinitionOptions.ImageDefinitionName, err)
	}

	l.Info("Successfully created image version for " + imageDefinitionOptions.ImageDefinitionName + ", ID: " + imageGalleryVersionID)

	if o.OutputFile != "" {
		resultSerialized, err := yaml.Marshal(result)
		if err != nil {
			return nil, fmt.Errorf("failed to serialize result: %w", err)
		}
		if err := ioutil.WriteFile(o.OutputFile, resultSerialized, 0644); err != nil {
			// Be nice and print the data so it doesn't get lost
			log.Log.Error(err, "Writing output file failed", "outputfile", o.OutputFile, "data", string(resultSerialized))
			return nil, fmt.Errorf("failed to write result to --output-file: %w", err)
		}
	}

	return &result, nil
}

func createRHCOSImageContainer(ctx context.Context, creds *apifixtures.AzureCreds, authorizer autorest.Authorizer, rg resources.Group, resourceGroupName string, location string, arch string) (bootImageID string, err error) {
	storageAccountClient := storage.NewAccountsClient(creds.SubscriptionID)
	storageAccountClient.Authorizer = authorizer

	storageAccountName := "cluster" + utilrand.String(5)
	storageAccountFuture, err := storageAccountClient.Create(ctx, *rg.Name, storageAccountName, storage.AccountCreateParameters{
		Sku:      &storage.Sku{Name: storage.SkuNamePremiumLRS, Tier: storage.SkuTierStandard},
		Location: utilpointer.String(location),
	})
	if err != nil {
		return "", fmt.Errorf("failed to create storage account: %w", err)
	}
	if err := storageAccountFuture.WaitForCompletionRef(ctx, storageAccountClient.Client); err != nil {
		return "", fmt.Errorf("failed waiting for storage account creation to complete: %w", err)
	}
	log.Log.Info("Successfuly created storage account", "name", storageAccountName)

	blobContainersClient := storage.NewBlobContainersClient(creds.SubscriptionID)
	blobContainersClient.Authorizer = authorizer

	vhd := "vhd-" + arch
	imageContainer, err := blobContainersClient.Create(ctx, *rg.Name, storageAccountName, vhd, storage.BlobContainer{})
	if err != nil {
		return "", fmt.Errorf("failed to create blob container: %w", err)
	}
	log.Log.Info("Successflly created blobcontainer", "name", *imageContainer.Name)

	// TODO: Extract this from the release image or require a parameter
	// Extraction is done like this:
	// docker run --rm -it --entrypoint cat quay.io/openshift-release-dev/ocp-release:4.10.0-rc.0-x86_64 release-manifests/0000_50_installer_coreos-bootimages.yaml |yaml2json |jq .data.stream -r|jq '.architectures.x86_64["rhel-coreos-extensions"]["azure-disk"].url'
	sourceURL, blobName := "", ""
	hyperVGenerationType := compute.HyperVGenerationTypesV1
	switch arch {
	case ArchitectureAMD64:
		sourceURL = "https://rhcos.blob.core.windows.net/imagebucket/rhcos-49.84.202110081407-0-azure.x86_64.vhd"
		blobName = "rhcos.x86_64.vhd"
	case ArchitectureARM64:
		sourceURL = "https://rhcos.blob.core.windows.net/imagebucket/rhcos-411.86.202206242256-0-azure.aarch64.vhd"
		blobName = "rhcos.aarch64.vhd"
		hyperVGenerationType = compute.HyperVGenerationTypesV2
	default:
		return "", fmt.Errorf("architecture not supported in manifest image, %s", arch)
	}

	// Explicitly check this, Azure API makes inferring the problem from the error message extremely hard
	if !strings.HasPrefix(sourceURL, "https://rhcos.blob.core.windows.net") {
		return "", fmt.Errorf("the image source url must be from an azure blob storage, otherwise upload will fail with an `One of the request inputs is out of range` error")
	}

	// storage object access has its own authentication system: https://github.com/hashicorp/terraform-provider-azurerm/blob/b0c897055329438be6a3a159f6ffac4e1ce958f2/internal/services/storage/client/client.go#L133
	accountsClient := storage.NewAccountsClient(creds.SubscriptionID)
	accountsClient.Authorizer = authorizer
	storageAccountKeyResult, err := accountsClient.ListKeys(ctx, resourceGroupName, storageAccountName, storage.ListKeyExpandKerb)
	if err != nil {
		return "", fmt.Errorf("failed to list storage account keys: %w", err)
	}
	if storageAccountKeyResult.Keys == nil || len(*storageAccountKeyResult.Keys) == 0 || (*storageAccountKeyResult.Keys)[0].Value == nil {
		return "", errors.New("no storage account keys exist")
	}
	blobAuth, err := autorest.NewSharedKeyAuthorizer(storageAccountName, *(*storageAccountKeyResult.Keys)[0].Value, autorest.SharedKey)
	if err != nil {
		return "", fmt.Errorf("failed to construct storage object authorizer: %w", err)
	}

	blobClient := blobs.New()
	blobClient.Authorizer = blobAuth
	log.Log.Info("Uploading rhcos image", "source", sourceURL)
	input := blobs.CopyInput{
		CopySource: sourceURL,
		MetaData: map[string]string{
			"source_uri": sourceURL,
		},
	}
	if err := blobClient.CopyAndWait(ctx, storageAccountName, vhd, blobName, input, 5*time.Second); err != nil {
		return "", fmt.Errorf("failed to upload rhcos image: %w", err)
	}
	log.Log.Info("Successfully uploaded rhcos image")

	imagesClient := compute.NewImagesClient(creds.SubscriptionID)
	imagesClient.Authorizer = authorizer

	imageBlobURL := "https://" + storageAccountName + ".blob.core.windows.net/" + vhd + "/" + blobName
	imageInput := compute.Image{
		ImageProperties: &compute.ImageProperties{
			StorageProfile: &compute.ImageStorageProfile{OsDisk: &compute.ImageOSDisk{
				OsType:  compute.OperatingSystemTypesLinux,
				OsState: compute.OperatingSystemStateTypesGeneralized,
				BlobURI: &imageBlobURL,
			}},
			HyperVGeneration: hyperVGenerationType,
		},
		Location: utilpointer.String(location),
	}
	imageCreationFuture, err := imagesClient.CreateOrUpdate(ctx, resourceGroupName, blobName, imageInput)
	if err != nil {
		return "", fmt.Errorf("failed to create image: %w", err)
	}
	if err := imageCreationFuture.WaitForCompletionRef(ctx, imagesClient.Client); err != nil {
		return "", fmt.Errorf("failed to wait for image creation to finish: %w", err)
	}
	imageCreationResult, err := imageCreationFuture.Result(imagesClient)
	if err != nil {
		return "", fmt.Errorf("failed to get imageCreationResult: %w", err)
	}
	bootImageID = *imageCreationResult.ID
	log.Log.Info("Successfully created image", "resourceID", *imageCreationResult.ID, "result", imageCreationResult)

	return bootImageID, nil
}

func findDNSZone(ctx context.Context, client dns.ZonesClient, name string) (*dns.Zone, error) {
	page, err := client.List(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to list DNS zones: %w", err)
	}
	for page.NotDone() {
		for _, item := range page.Values() {
			if *item.Name == name {
				return &item, nil
			}
			if err := page.NextWithContext(ctx); err != nil {
				return nil, fmt.Errorf("failed to fetch DNS zone page: %w", err)
			}
		}
	}

	return nil, fmt.Errorf("no dns zone with name %s found", name)
}

func createGallery(ctx context.Context, resourceGroupName string, imageGalleryName string, subscriptionID string, location string, cred azcore.TokenCredential, diskID string) (*armcompute.Gallery, error) {
	galleriesClient, err := armcompute.NewGalleriesClient(subscriptionID, cred, nil)
	if err != nil {
		return nil, err
	}

	pollerResp, err := galleriesClient.BeginCreateOrUpdate(
		ctx,
		resourceGroupName,
		imageGalleryName,
		armcompute.Gallery{
			Location: to.Ptr(location),
			Properties: &armcompute.GalleryProperties{
				Description: to.Ptr("Contains boot images to initialize NodePool nodes"),
			},
		},
		nil,
	)
	if err != nil {
		return nil, err
	}

	resp, err := pollerResp.PollUntilDone(ctx, nil)
	if err != nil {
		return nil, err
	}

	return &resp.Gallery, nil
}

func createDisk(ctx context.Context, resourceGroupName string, subscriptionID string, location string, cred azcore.TokenCredential) (*armcompute.Disk, error) {
	disksClient, err := armcompute.NewDisksClient(subscriptionID, cred, nil)
	if err != nil {
		return nil, err
	}

	pollerResp, err := disksClient.BeginCreateOrUpdate(
		ctx,
		resourceGroupName,
		DiskName,
		armcompute.Disk{
			Location: to.Ptr(location),
			SKU: &armcompute.DiskSKU{
				Name: to.Ptr(armcompute.DiskStorageAccountTypesStandardLRS),
			},
			Properties: &armcompute.DiskProperties{
				CreationData: &armcompute.CreationData{
					CreateOption: to.Ptr(armcompute.DiskCreateOptionEmpty),
				},
				DiskSizeGB: to.Ptr[int32](128),
			},
		},
		nil,
	)
	if err != nil {
		return nil, err
	}

	resp, err := pollerResp.PollUntilDone(ctx, nil)
	if err != nil {
		return nil, err
	}

	return &resp.Disk, nil
}

func createGalleryImageDefinition(imageDefinitionOptions *GalleryImageDefinitionOptions) (string, error) {
	galleryImageProperties := &armcompute.GalleryImageProperties{
		Identifier: &armcompute.GalleryImageIdentifier{
			Offer:     to.Ptr(imageDefinitionOptions.ImageDefinitionName),
			Publisher: to.Ptr("RedHat"),
			SKU:       to.Ptr("basic"),
		},
		OSType:  to.Ptr(armcompute.OperatingSystemTypesLinux),
		OSState: to.Ptr(armcompute.OperatingSystemStateTypesGeneralized),
	}
	switch imageDefinitionOptions.Arch {
	case ArchitectureARM64:
		galleryImageProperties.HyperVGeneration = to.Ptr(armcompute.HyperVGenerationV2)
		galleryImageProperties.Architecture = to.Ptr(armcompute.ArchitectureArm64)
	case ArchitectureAMD64:
		galleryImageProperties.HyperVGeneration = to.Ptr(armcompute.HyperVGenerationV1)
		galleryImageProperties.Architecture = to.Ptr(armcompute.ArchitectureX64)
	default:
		return "", fmt.Errorf("failed to create image definition. Architecture not supported for %s", imageDefinitionOptions.Arch)
	}

	imageTemplate := armcompute.GalleryImage{
		Location:   to.Ptr(imageDefinitionOptions.Location),
		Properties: galleryImageProperties,
	}

	galleryImageDefinition, err := createImageDefinition(imageDefinitionOptions, imageTemplate)
	if err != nil {
		return "", fmt.Errorf("failed to create image definition for %s: %w", imageDefinitionOptions.ImageDefinitionName, err)
	}

	return *galleryImageDefinition.ID, nil
}

func createImageDefinition(imageDefinitionOptions *GalleryImageDefinitionOptions, galleryImage armcompute.GalleryImage) (*armcompute.GalleryImage, error) {
	galleryImageClient, err := armcompute.NewGalleryImagesClient(imageDefinitionOptions.SubscriptionID, imageDefinitionOptions.AzureCreds, nil)
	if err != nil {
		return nil, err
	}

	pollerResp, err := galleryImageClient.BeginCreateOrUpdate(imageDefinitionOptions.Context, imageDefinitionOptions.ResourceGroupName, imageDefinitionOptions.ImageGalleryName, imageDefinitionOptions.ImageDefinitionName, galleryImage, nil)
	if err != nil {
		return nil, err
	}

	resp, err := pollerResp.PollUntilDone(imageDefinitionOptions.Context, nil)
	if err != nil {
		return nil, err
	}

	return &resp.GalleryImage, nil
}

func createGalleryImageDefinitionVersion(imageDefinitionOptions *GalleryImageDefinitionOptions) (string, error) {
	galleryImageVersionClient, err := armcompute.NewGalleryImageVersionsClient(imageDefinitionOptions.SubscriptionID, imageDefinitionOptions.AzureCreds, nil)
	if err != nil {
		return "", fmt.Errorf("failed to create a gallery image version client for %s: %w", imageDefinitionOptions.ImageGalleryName, err)
	}

	galleryImageVersion := armcompute.GalleryImageVersion{
		Location: to.Ptr(imageDefinitionOptions.Location),
		Properties: &armcompute.GalleryImageVersionProperties{
			StorageProfile: &armcompute.GalleryImageVersionStorageProfile{
				Source: &armcompute.GalleryArtifactVersionSource{
					ID: to.Ptr(imageDefinitionOptions.BootImageID),
				},
			},
		},
	}

	imageVersionRsp, err := galleryImageVersionClient.BeginCreateOrUpdate(imageDefinitionOptions.Context, imageDefinitionOptions.ResourceGroupName, imageDefinitionOptions.ImageGalleryName, imageDefinitionOptions.ImageDefinitionName, "1.0.0", galleryImageVersion, nil)
	if err != nil {
		return "", fmt.Errorf("failed create image definition version for %s: %w", imageDefinitionOptions.ImageDefinitionName, err)
	}
	resp, err := imageVersionRsp.PollUntilDone(imageDefinitionOptions.Context, nil)
	if err != nil {
		return "", fmt.Errorf("failed waiting for image definition version creation to finish for %s: %w", imageDefinitionOptions.ImageDefinitionName, err)
	}

	return *resp.ID, nil
}
