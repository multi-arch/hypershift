package nodepool

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"fmt"
	"strings"

	"golang.org/x/crypto/ssh"
	utilpointer "k8s.io/utils/pointer"
	capiazure "sigs.k8s.io/cluster-api-provider-azure/api/v1beta1"

	hyperv1 "github.com/openshift/hypershift/api/v1alpha1"
)

func azureMachineTemplateSpec(hcluster *hyperv1.HostedCluster, nodePool *hyperv1.NodePool, existing capiazure.AzureMachineTemplateSpec) (*capiazure.AzureMachineTemplateSpec, error) {
	// The azure api requires to pass a public key. This key is randomly generated, the private portion is thrown away and the public key
	// gets written to the template.
	sshKey := existing.Template.Spec.SSHPublicKey
	if sshKey == "" {
		var err error
		sshKey, err = generateSSHPubkey()
		if err != nil {
			return nil, fmt.Errorf("failed to generate a SSH key: %w", err)
		}
	}

	bootImageToUse, err := bootImage(hcluster, nodePool)
	if err != nil {
		return nil, fmt.Errorf("failed to find boot image: %w", err)
	}

	return &capiazure.AzureMachineTemplateSpec{Template: capiazure.AzureMachineTemplateResource{Spec: capiazure.AzureMachineSpec{
		VMSize: nodePool.Spec.Platform.Azure.VMSize,
		Image:  &capiazure.Image{ID: utilpointer.String(bootImageToUse)},
		OSDisk: capiazure.OSDisk{
			DiskSizeGB: utilpointer.Int32Ptr(nodePool.Spec.Platform.Azure.DiskSizeGB),
			ManagedDisk: &capiazure.ManagedDiskParameters{
				StorageAccountType: nodePool.Spec.Platform.Azure.DiskStorageAccountType,
			},
		},
		SubnetName:             hcluster.Spec.Platform.Azure.SubnetName,
		Identity:               capiazure.VMIdentityUserAssigned,
		UserAssignedIdentities: []capiazure.UserAssignedIdentity{{ProviderID: hcluster.Spec.Platform.Azure.MachineIdentityID}},
		SSHPublicKey:           sshKey,
		FailureDomain:          failureDomain(nodePool),
	}}}, nil
}

func generateSSHPubkey() (string, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return "", fmt.Errorf("failed to generate private key: %w", err)
	}

	publicRsaKey, err := ssh.NewPublicKey(&privateKey.PublicKey)
	if err != nil {
		return "", fmt.Errorf("failed to generate public key: %w", err)
	}

	return base64.StdEncoding.EncodeToString(ssh.MarshalAuthorizedKey(publicRsaKey)), nil
}

func bootImage(hcluster *hyperv1.HostedCluster, nodepool *hyperv1.NodePool) (string, error) {
	var bootImageGalleyID string
	splitResourceGroupName := strings.Split(hcluster.Spec.Platform.Azure.ResourceGroupName, "-")
	if len(splitResourceGroupName) <= 0 {
		return "", fmt.Errorf("failed to parse resource group name unique ID to retrieve boot image: %s", hcluster.Spec.Platform.Azure.ResourceGroupName)
	} else {
		bootImageGalleyID = splitResourceGroupName[len(splitResourceGroupName)-1]
	}

	switch nodepool.Spec.Arch {
	case "amd64":
		return fmt.Sprintf("/subscriptions/%s/resourceGroups/%s/providers/Microsoft.Compute/galleries/BootImageGallery_%s/images/RHCOS_Amd64/versions/1.0.0", hcluster.Spec.Platform.Azure.SubscriptionID, hcluster.Spec.Platform.Azure.ResourceGroupName, bootImageGalleyID), nil
	case "arm64":
		return fmt.Sprintf("/subscriptions/%s/resourceGroups/%s/providers/Microsoft.Compute/galleries/BootImageGallery_%s/images/RHCOS_Arm64/versions/1.0.0", hcluster.Spec.Platform.Azure.SubscriptionID, hcluster.Spec.Platform.Azure.ResourceGroupName, bootImageGalleyID), nil
	default:
		return "", fmt.Errorf("invalid boot architecture received: %s", nodepool.Spec.Arch)
	}
}

func failureDomain(nodepool *hyperv1.NodePool) *string {
	if nodepool.Spec.Platform.Azure.AvailabilityZone == "" {
		return nil
	}
	return utilpointer.String(nodepool.Spec.Platform.Azure.AvailabilityZone)
}
