package azure

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/openshift/hypershift/api/fixtures"
	hyperv1 "github.com/openshift/hypershift/api/hypershift/v1beta1"
	"github.com/openshift/hypershift/cmd/log"
	"github.com/openshift/hypershift/cmd/util"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/authorization/armauthorization"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/compute/armcompute"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/dns/armdns"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/msi/armmsi"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/network/armnetwork"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/privatedns/armprivatedns"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armresources"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/storage/armstorage"
	"github.com/Azure/go-autorest/autorest"

	utilrand "k8s.io/apimachinery/pkg/util/rand"
	"sigs.k8s.io/yaml"

	"github.com/go-logr/logr"
	"github.com/hashicorp/go-uuid"
	"github.com/spf13/cobra"

	// This is the same client as terraform uses: https://github.com/hashicorp/terraform-provider-azurerm/blob/b0c897055329438be6a3a159f6ffac4e1ce958f2/internal/services/storage/blobs.go#L17
	// The one from the azure sdk is cumbersome to use (distinct authorizer, requires to manually construct the full target url), and only allows upload from url for files that are not bigger than 256M.
	"github.com/tombuildsstuff/giovanni/storage/2019-12-12/blob/blobs"
)

const (
	SubnetName                        = "default"
	VirtualNetworkAddressPrefix       = "10.0.0.0/16"
	VirtualNetworkLinkLocation        = "global"
	VirtualNetworkSubnetAddressPrefix = "10.0.0.0/24"
)

type CreateInfraOptions struct {
	Name              string
	BaseDomain        string
	Location          string
	InfraID           string
	CredentialsFile   string
	Credentials       *util.AzureCreds
	OutputFile        string
	RHCOSImage        map[string]string
	Arch              string
	ResourceGroupName string
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
	InfraID           string `json:"infraID"`
	MachineIdentityID string `json:"machineIdentityID"`
	SecurityGroupName string `json:"securityGroupName"`

	BootImageInfo map[string]fixtures.BootImageDetails `json:"bootImageInfo"`
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
	cmd.Flags().StringVar(&opts.ResourceGroupName, "resource-group-name", opts.ResourceGroupName, "A resource group name to create the HostedCluster infrastructure resources under.")
	cmd.Flags().StringVar(&opts.OutputFile, "output-file", opts.OutputFile, "Path to file that will contain output information from infra resources (optional)")

	_ = cmd.MarkFlagRequired("infra-id")
	_ = cmd.MarkFlagRequired("azure-creds")
	_ = cmd.MarkFlagRequired("name")

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

func (o *CreateInfraOptions) Run(ctx context.Context, l logr.Logger) (*CreateInfraOutput, error) {
	result := CreateInfraOutput{
		Location:      o.Location,
		InfraID:       o.InfraID,
		BaseDomain:    o.BaseDomain,
		BootImageInfo: make(map[string]fixtures.BootImageDetails),
	}

	// Setup subscription ID and Azure credential information
	subscriptionID, azureCreds, err := util.SetupAzureCredentials(l, o.Credentials, o.CredentialsFile)
	if err != nil {
		return nil, fmt.Errorf("failed to setup Azure credentials: %w", err)
	}

	// Create an Azure resource group
	resourceGroupID, resourceGroupName, msg, err := createResourceGroup(ctx, o, azureCreds, subscriptionID)
	if err != nil {
		return nil, fmt.Errorf("failed to create a resource group: %w", err)
	}
	result.ResourceGroupName = resourceGroupName
	l.Info(msg, "name", resourceGroupName)

	// Capture the base DNS zone's resource group's ID
	result.PublicZoneID, err = getBaseDomainID(ctx, subscriptionID, azureCreds, o.BaseDomain)
	if err != nil {
		return nil, err
	}

	// Create the managed identity
	identityID, identityRolePrincipalID, err := createManagedIdentity(ctx, subscriptionID, resourceGroupName, o.Name, o.InfraID, o.Location, azureCreds)
	if err != nil {
		return nil, err
	}
	result.MachineIdentityID = identityID
	l.Info("Successfully created managed identity", "name", identityID)

	// Assign 'Contributor' role definition to managed identity
	l.Info("Assigning role to managed identity, this may take some time")
	err = setManagedIdentityRole(ctx, subscriptionID, resourceGroupID, identityRolePrincipalID, azureCreds)
	if err != nil {
		return nil, err
	}
	l.Info("Successfully assigned contributor role to managed identity", "name", identityID)

	// Create network security group
	securityGroupName, securityGroupID, err := createSecurityGroup(ctx, subscriptionID, resourceGroupName, o.Name, o.InfraID, o.Location, azureCreds)
	if err != nil {
		return nil, err
	}
	result.SecurityGroupName = securityGroupName
	l.Info("Successfully created network security group", "name", securityGroupName)

	// Create virtual network
	subnetName, vnetID, vnetName, err := createVirtualNetwork(ctx, subscriptionID, resourceGroupName, o.Name, o.InfraID, o.Location, securityGroupID, azureCreds)
	if err != nil {
		return nil, err
	}
	result.SubnetName = subnetName
	result.VNetID = vnetID
	result.VnetName = vnetName
	l.Info("Successfully created vnet", "name", vnetName)

	// Create private DNS zone
	privateDNSZoneID, privateDNSZoneName, err := createPrivateDNSZone(ctx, subscriptionID, resourceGroupName, o.Name, o.BaseDomain, azureCreds)
	if err != nil {
		return nil, err
	}
	result.PrivateZoneID = privateDNSZoneID
	l.Info("Successfully created private DNS zone", "name", privateDNSZoneName)

	// Create private DNS zone link
	err = createPrivateDNSZoneLink(ctx, subscriptionID, resourceGroupName, o.Name, o.InfraID, vnetID, privateDNSZoneName, azureCreds)
	if err != nil {
		return nil, err
	}
	l.Info("Successfully created private DNS zone link")

	// Upload RHCOS image and create a bootable image
	bootImageID, err := createRhcosImages(ctx, l, o, o.Arch, subscriptionID, resourceGroupName, azureCreds)
	if err != nil {
		return nil, fmt.Errorf("failed to create RHCOS image: %w", err)
	}
	result.BootImageInfo[o.Arch] = fixtures.BootImageDetails{BootImageID: bootImageID}

	if o.Arch == hyperv1.ArchitectureARM64 {
		// Upload the amd64 RHCOS image as well
		bootImageID, err = createRhcosImages(ctx, l, o, hyperv1.ArchitectureAMD64, subscriptionID, resourceGroupName, azureCreds)
		if err != nil {
			return nil, fmt.Errorf("failed to create RHCOS image: %w", err)
		}
		result.BootImageInfo[hyperv1.ArchitectureAMD64] = fixtures.BootImageDetails{BootImageID: bootImageID}
	}

	if o.OutputFile != "" {
		resultSerialized, err := yaml.Marshal(result)
		if err != nil {
			return nil, fmt.Errorf("failed to serialize result: %w", err)
		}
		if err := os.WriteFile(o.OutputFile, resultSerialized, 0644); err != nil {
			// Be nice and print the data, so it doesn't get lost
			log.Log.Error(err, "Writing output file failed", "Output File", o.OutputFile, "data", string(resultSerialized))
			return nil, fmt.Errorf("failed to write result to --output-file: %w", err)
		}
	}

	return &result, nil

}

// createResourceGroup creates the Azure resource group used to group all Azure infrastructure resources
func createResourceGroup(ctx context.Context, o *CreateInfraOptions, azureCreds azcore.TokenCredential, subscriptionID string) (string, string, string, error) {
	existingRGSuccessMsg := "Successfully found existing resource group"
	createdRGSuccessMsg := "Successfully created resource group"

	resourceGroupClient, err := armresources.NewResourceGroupsClient(subscriptionID, azureCreds, nil)
	if err != nil {
		return "", "", "", fmt.Errorf("failed to create new resource groups client: %w", err)
	}

	// Use provided resource group if it was provided
	if o.ResourceGroupName != "" {
		response, err := resourceGroupClient.Get(ctx, o.ResourceGroupName, nil)
		if err != nil {
			return "", "", "", fmt.Errorf("failed to get resource group name, '%s': %w", o.ResourceGroupName, err)
		}

		return *response.ID, *response.Name, existingRGSuccessMsg, nil
	} else {
		// Create a resource group since none was provided
		resourceGroupName := o.Name + "-" + o.InfraID
		parameters := armresources.ResourceGroup{
			Location: to.Ptr(o.Location),
		}
		response, err := resourceGroupClient.CreateOrUpdate(ctx, resourceGroupName, parameters, nil)
		if err != nil {
			return "", "", "", fmt.Errorf("createResourceGroup: failed to create a resource group: %w", err)
		}

		return *response.ID, *response.Name, createdRGSuccessMsg, nil
	}
}

// getBaseDomainID gets the resource group ID for the resource group containing the base domain
func getBaseDomainID(ctx context.Context, subscriptionID string, azureCreds azcore.TokenCredential, baseDomain string) (string, error) {
	zonesClient, err := armdns.NewZonesClient(subscriptionID, azureCreds, nil)
	if err != nil {
		return "", fmt.Errorf("failed to create dns zone %s: %w", baseDomain, err)
	}

	pager := zonesClient.NewListPager(nil)
	if pager.More() {
		pagerResults, err := pager.NextPage(ctx)
		if err != nil {
			return "", fmt.Errorf("failed to retrieve list of DNS zones: %w", err)
		}

		for _, result := range pagerResults.Value {
			if *result.Name == baseDomain {
				return *result.ID, nil
			}
		}
	}
	return "", fmt.Errorf("could not find any DNS zones in subscription")
}

// createManagedIdentity creates a managed identity
func createManagedIdentity(ctx context.Context, subscriptionID string, resourceGroupName string, name string, infraID string, location string, azureCreds azcore.TokenCredential) (string, string, error) {
	identityClient, err := armmsi.NewUserAssignedIdentitiesClient(subscriptionID, azureCreds, nil)
	if err != nil {
		return "", "", fmt.Errorf("failed to create new identity client: %w", err)
	}
	identity, err := identityClient.CreateOrUpdate(ctx, resourceGroupName, name+"-"+infraID, armmsi.Identity{Location: &location}, nil)
	if err != nil {
		return "", "", fmt.Errorf("failed to create managed identity: %w", err)
	}
	return *identity.ID, *identity.Properties.PrincipalID, nil
}

// setManagedIdentityRole sets the managed identity's principal role to 'Contributor'
func setManagedIdentityRole(ctx context.Context, subscriptionID string, resourceGroupID string, identityRolePrincipalID string, azureCreds azcore.TokenCredential) error {
	roleDefinitionClient, err := armauthorization.NewRoleDefinitionsClient(azureCreds, nil)
	if err != nil {
		return fmt.Errorf("failed to create new role definitions client: %w", err)
	}

	found := false
	var roleDefinition *armauthorization.RoleDefinition = nil
	roleDefinitionsResponse := roleDefinitionClient.NewListPager(resourceGroupID, nil)
	for roleDefinitionsResponse.More() && !found {
		page, err := roleDefinitionsResponse.NextPage(ctx)
		if err != nil {
			return fmt.Errorf("failed to retrieve next page for role definitions: %w", err)
		}

		for _, role := range page.Value {
			if *role.Properties.RoleName == "Contributor" {
				roleDefinition = role
				found = true
				break
			}
		}
	}

	if roleDefinition == nil {
		return fmt.Errorf("didn't find the 'Contributor' role")
	}

	roleAssignmentClient, err := armauthorization.NewRoleAssignmentsClient(subscriptionID, azureCreds, nil)
	if err != nil {
		return fmt.Errorf("failed to create new role assignments client: %w", err)
	}

	roleAssignmentName, err := uuid.GenerateUUID()
	if err != nil {
		return fmt.Errorf("failed to generate uuid for role assignment name: %w", err)
	}

	for try := 0; try < 100; try++ {
		_, err := roleAssignmentClient.Create(ctx, resourceGroupID, roleAssignmentName,
			armauthorization.RoleAssignmentCreateParameters{
				Properties: &armauthorization.RoleAssignmentProperties{
					RoleDefinitionID: roleDefinition.ID,
					PrincipalID:      to.Ptr(identityRolePrincipalID),
				},
			}, nil)
		if err != nil {
			if try < 99 {
				time.Sleep(time.Second)
				continue
			}
			return fmt.Errorf("failed to add role assignment to role: %w", err)
		}
		break
	}
	return nil
}

// createSecurityGroup creates the security group the virtual network will use
func createSecurityGroup(ctx context.Context, subscriptionID string, resourceGroupName string, name string, infraID string, location string, azureCreds azcore.TokenCredential) (string, string, error) {
	securityGroupClient, err := armnetwork.NewSecurityGroupsClient(subscriptionID, azureCreds, nil)
	if err != nil {
		return "", "", fmt.Errorf("failed to create security group client: %w", err)
	}
	securityGroupFuture, err := securityGroupClient.BeginCreateOrUpdate(ctx, resourceGroupName, name+"-"+infraID+"-nsg", armnetwork.SecurityGroup{Location: &location}, nil)
	if err != nil {
		return "", "", fmt.Errorf("failed to create network security group: %w", err)
	}
	securityGroup, err := securityGroupFuture.PollUntilDone(ctx, nil)
	if err != nil {
		return "", "", fmt.Errorf("failed to get network security group creation result: %w", err)
	}

	return *securityGroup.Name, *securityGroup.ID, nil
}

// createVirtualNetwork creates the virtual network
func createVirtualNetwork(ctx context.Context, subscriptionID string, resourceGroupName string, name string, infraID string, location string, securityGroupID string, azureCreds azcore.TokenCredential) (string, string, string, error) {
	networksClient, err := armnetwork.NewVirtualNetworksClient(subscriptionID, azureCreds, nil)
	if err != nil {
		return "", "", "", fmt.Errorf("failed to create new virtual networks client: %w", err)
	}

	vnetFuture, err := networksClient.BeginCreateOrUpdate(ctx, resourceGroupName, name+"-"+infraID, armnetwork.VirtualNetwork{
		Location: &location,
		Properties: &armnetwork.VirtualNetworkPropertiesFormat{
			AddressSpace: &armnetwork.AddressSpace{
				AddressPrefixes: []*string{
					to.Ptr(VirtualNetworkAddressPrefix),
				},
			},
			Subnets: []*armnetwork.Subnet{{
				Name: to.Ptr(SubnetName),
				Properties: &armnetwork.SubnetPropertiesFormat{
					AddressPrefix:        to.Ptr(VirtualNetworkSubnetAddressPrefix),
					NetworkSecurityGroup: &armnetwork.SecurityGroup{ID: &securityGroupID},
				},
			}},
		},
	}, nil)
	if err != nil {
		return "", "", "", fmt.Errorf("failed to create vnet: %w", err)
	}
	vnet, err := vnetFuture.PollUntilDone(ctx, nil)
	if err != nil {
		return "", "", "", fmt.Errorf("failed to wait for vnet creation: %w", err)
	}
	if vnet.Properties.Subnets == nil || len(vnet.Properties.Subnets) < 1 {
		return "", "", "", fmt.Errorf("created vnet has no subnets: %+v", vnet)
	}

	return *(vnet.Properties.Subnets)[0].Name, *vnet.ID, *vnet.Name, nil
}

// createPrivateDNSZone creates the private DNS zone
func createPrivateDNSZone(ctx context.Context, subscriptionID string, resourceGroupName string, name string, baseDomain string, azureCreds azcore.TokenCredential) (string, string, error) {
	privateZoneClient, err := armprivatedns.NewPrivateZonesClient(subscriptionID, azureCreds, nil)
	if err != nil {
		return "", "", fmt.Errorf("failed to create new private zones client: %w", err)
	}
	privateZoneParams := armprivatedns.PrivateZone{
		Location: to.Ptr("global"),
	}
	privateDNSZonePromise, err := privateZoneClient.BeginCreateOrUpdate(ctx, resourceGroupName, name+"-azurecluster."+baseDomain, privateZoneParams, nil)
	if err != nil {
		return "", "", fmt.Errorf("failed to create private DNS zone: %w", err)
	}
	privateDNSZone, err := privateDNSZonePromise.PollUntilDone(ctx, nil)
	if err != nil {
		return "", "", fmt.Errorf("failed waiting for private DNS zone completion: %w", err)
	}

	return *privateDNSZone.ID, *privateDNSZone.Name, nil
}

// createPrivateDNSZoneLink creates the private DNS Zone network link
func createPrivateDNSZoneLink(ctx context.Context, subscriptionID string, resourceGroupName string, name string, infraID string, vnetID string, privateDNSZoneName string, azureCreds azcore.TokenCredential) error {
	privateZoneLinkClient, err := armprivatedns.NewVirtualNetworkLinksClient(subscriptionID, azureCreds, nil)
	if err != nil {
		return fmt.Errorf("failed to create new virtual network links client: %w", err)
	}

	virtualNetworkLinkParams := armprivatedns.VirtualNetworkLink{
		Location: to.Ptr(VirtualNetworkLinkLocation),
		Properties: &armprivatedns.VirtualNetworkLinkProperties{
			VirtualNetwork:      &armprivatedns.SubResource{ID: &vnetID},
			RegistrationEnabled: to.Ptr(false),
		},
	}
	networkLinkPromise, err := privateZoneLinkClient.BeginCreateOrUpdate(ctx, resourceGroupName, privateDNSZoneName, name+"-"+infraID, virtualNetworkLinkParams, nil)
	if err != nil {
		return fmt.Errorf("failed to set up network link for private DNS zone: %w", err)
	}
	_, err = networkLinkPromise.PollUntilDone(ctx, nil)
	if err != nil {
		return fmt.Errorf("failed waiting for network link for private DNS zone: %w", err)
	}

	return nil
}

// createRhcosImages uploads the RHCOS image and creates a bootable image
func createRhcosImages(ctx context.Context, l logr.Logger, o *CreateInfraOptions, arch string, subscriptionID string, resourceGroupName string, azureCreds azcore.TokenCredential) (string, error) {
	storageAccountClient, err := armstorage.NewAccountsClient(subscriptionID, azureCreds, nil)
	if err != nil {
		return "", fmt.Errorf("failed to create new accounts client for storage: %w", err)
	}

	storageAccountName := "cluster" + utilrand.String(5)
	storageAccountFuture, err := storageAccountClient.BeginCreate(ctx, resourceGroupName, storageAccountName,
		armstorage.AccountCreateParameters{
			SKU: &armstorage.SKU{
				Name: to.Ptr(armstorage.SKUNamePremiumLRS),
				Tier: to.Ptr(armstorage.SKUTierStandard),
			},
			Location: to.Ptr(o.Location),
		}, nil)
	if err != nil {
		return "", fmt.Errorf("failed to create storage account: %w", err)
	}
	storageAccount, err := storageAccountFuture.PollUntilDone(ctx, nil)
	if err != nil {
		return "", fmt.Errorf("failed waiting for storage account creation to complete: %w", err)
	}
	l.Info("Successfully created storage account", "name", *storageAccount.Name)

	blobContainersClient, err := armstorage.NewBlobContainersClient(subscriptionID, azureCreds, nil)
	if err != nil {
		return "", fmt.Errorf("failed to create blob containers client: %w", err)
	}

	imageContainer, err := blobContainersClient.Create(ctx, resourceGroupName, storageAccountName, "vhd", armstorage.BlobContainer{}, nil)
	if err != nil {
		return "", fmt.Errorf("failed to create blob container: %w", err)
	}
	l.Info("Successfully created blob container", "name", *imageContainer.Name)

	sourceURL := o.RHCOSImage[arch]
	blobName := "rhcos." + arch + ".vhd"

	// Explicitly check this, Azure API makes inferring the problem from the error message extremely hard
	if !strings.HasPrefix(sourceURL, "https://rhcos.blob.core.windows.net") {
		return "", fmt.Errorf("the image source url must be from an azure blob storage, otherwise upload will fail with an `One of the request inputs is out of range` error")
	}

	// storage object access has its own authentication system: https://github.com/hashicorp/terraform-provider-azurerm/blob/b0c897055329438be6a3a159f6ffac4e1ce958f2/internal/services/storage/client/client.go#L133
	accountsClient, err := armstorage.NewAccountsClient(subscriptionID, azureCreds, nil)
	if err != nil {
		return "", fmt.Errorf("failed to create new accounts client: %w", err)
	}
	storageAccountKeyResult, err := accountsClient.ListKeys(ctx, resourceGroupName, storageAccountName, &armstorage.AccountsClientListKeysOptions{Expand: to.Ptr("kerb")})
	if err != nil {
		return "", fmt.Errorf("failed to list storage account keys: %w", err)
	}
	if storageAccountKeyResult.Keys == nil || len(storageAccountKeyResult.Keys) == 0 || storageAccountKeyResult.Keys[0].Value == nil {
		return "", errors.New("no storage account keys exist")
	}
	blobAuth, err := autorest.NewSharedKeyAuthorizer(storageAccountName, *storageAccountKeyResult.Keys[0].Value, autorest.SharedKey)
	if err != nil {
		return "", fmt.Errorf("failed to construct storage object authorizer: %w", err)
	}

	blobClient := blobs.New()
	blobClient.Authorizer = blobAuth
	l.Info("Uploading rhcos image", "source", sourceURL)
	input := blobs.CopyInput{
		CopySource: sourceURL,
		MetaData: map[string]string{
			"source_uri": sourceURL,
		},
	}
	if err := blobClient.CopyAndWait(ctx, storageAccountName, "vhd", blobName, input, 5*time.Second); err != nil {
		return "", fmt.Errorf("failed to upload rhcos image: %w", err)
	}
	l.Info("Successfully uploaded rhcos image")

	imagesClient, err := armcompute.NewImagesClient(subscriptionID, azureCreds, nil)
	if err != nil {
		return "", fmt.Errorf("failed to create images client: %w", err)
	}

	imageBlobURL := "https://" + storageAccountName + ".blob.core.windows.net/" + "vhd" + "/" + blobName
	imageInput := armcompute.Image{
		Properties: &armcompute.ImageProperties{
			StorageProfile: &armcompute.ImageStorageProfile{
				OSDisk: &armcompute.ImageOSDisk{
					OSType:  to.Ptr(armcompute.OperatingSystemTypesLinux),
					OSState: to.Ptr(armcompute.OperatingSystemStateTypesGeneralized),
					BlobURI: to.Ptr(imageBlobURL),
				},
			},
			HyperVGeneration: to.Ptr(armcompute.HyperVGenerationTypesV2),
		},
		Location: to.Ptr(o.Location),
	}
	imageCreationFuture, err := imagesClient.BeginCreateOrUpdate(ctx, resourceGroupName, blobName, imageInput, nil)
	if err != nil {
		return "", fmt.Errorf("failed to create image: %w", err)
	}
	imageCreationResult, err := imageCreationFuture.PollUntilDone(ctx, nil)
	if err != nil {
		return "", fmt.Errorf("failed to wait for image creation to finish: %w", err)
	}
	bootImageID := *imageCreationResult.ID
	l.Info("Successfully created image", "resourceID", *imageCreationResult.ID, "result", imageCreationResult)

	return bootImageID, nil
}
