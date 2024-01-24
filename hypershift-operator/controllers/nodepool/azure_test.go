package nodepool

import (
	"testing"

	hyperv1 "github.com/openshift/hypershift/api/hypershift/v1beta1"
)

func TestBootImage(t *testing.T) {
	testCases := []struct {
		name          string
		hostedCluster *hyperv1.HostedCluster
		nodepool      *hyperv1.NodePool
		expected      string
	}{
		{
			name: "Nodepool has image set, it is being used",
			nodepool: &hyperv1.NodePool{
				Spec: hyperv1.NodePoolSpec{
					Platform: hyperv1.NodePoolPlatform{
						Azure: &hyperv1.AzureNodePoolPlatform{
							ImageID: "nodepool-image",
						}},
					Arch: "amd64",
				}},
			expected: "nodepool-image",
		},
		{
			name: "Default boot image is used",
			hostedCluster: &hyperv1.HostedCluster{Spec: hyperv1.HostedClusterSpec{Platform: hyperv1.PlatformSpec{Azure: &hyperv1.AzurePlatformSpec{
				SubscriptionID:    "123-123",
				ResourceGroupName: "rg-name",
			}}}},
			nodepool: &hyperv1.NodePool{
				Spec: hyperv1.NodePoolSpec{
					Platform: hyperv1.NodePoolPlatform{
						Azure: &hyperv1.AzureNodePoolPlatform{}},
					Arch: "arm64",
				}},
			expected: "/subscriptions/123-123/resourceGroups/rg-name/providers/Microsoft.Compute/images/rhcos.arm64.vhd",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := bootImage(tc.hostedCluster, tc.nodepool)
			if result != tc.expected {
				t.Errorf("expected %s, got %s", tc.expected, result)
			}
		})
	}
}
