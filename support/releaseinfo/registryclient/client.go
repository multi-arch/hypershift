package registryclient

import (
	"archive/tar"
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/docker/distribution"
	"github.com/docker/distribution/manifest/manifestlist"
	"github.com/docker/distribution/registry/client/transport"
	"github.com/opencontainers/go-digest"
	"k8s.io/client-go/rest"

	"github.com/openshift/hypershift/support/thirdparty/library-go/pkg/image/registryclient"

	dockerarchive "github.com/openshift/hypershift/support/thirdparty/docker/pkg/archive"
	"github.com/openshift/hypershift/support/thirdparty/library-go/pkg/image/reference"
	"github.com/openshift/hypershift/support/thirdparty/oc/pkg/cli/image/manifest"
	"github.com/openshift/hypershift/support/thirdparty/oc/pkg/cli/image/manifest/dockercredentials"
)

// ExtractImageFiles extracts a list of files from a registry image given the image reference, pull secret and the
// list of files to extract. It returns a map with file contents or an error.
func ExtractImageFiles(ctx context.Context, imageRef string, pullSecret []byte, files ...string) (map[string][]byte, error) {
	layers, fromBlobs, err := getMetadata(ctx, imageRef, pullSecret)
	if err != nil {
		return nil, err
	}

	fileContents := map[string][]byte{}
	for _, file := range files {
		fileContents[file] = nil
	}
	if len(fileContents) == 0 {
		return fileContents, nil
	}

	// Iterate over layers in reverse order to find the most recent version of files
	for i := len(layers) - 1; i >= 0; i-- {
		layer := layers[i]
		err := func() error {
			r, err := fromBlobs.Open(ctx, layer.Digest)
			if err != nil {
				return fmt.Errorf("unable to access the source layer %s: %v", layer.Digest, err)
			}
			defer r.Close()
			rc, err := dockerarchive.DecompressStream(r)
			if err != nil {
				return err
			}
			defer rc.Close()
			tr := tar.NewReader(rc)
			for {
				hdr, err := tr.Next()
				if err != nil {
					if err == io.EOF {
						break
					}
					return err
				}
				if hdr.Typeflag == tar.TypeReg {
					value, needFile := fileContents[hdr.Name]
					if !needFile {
						continue
					}
					// If value already assigned, the content was found in an earlier layer
					if value != nil {
						continue
					}
					out := &bytes.Buffer{}
					if _, err := io.Copy(out, tr); err != nil {
						return err
					}
					fileContents[hdr.Name] = out.Bytes()
				}
				if allFound(fileContents) {
					break
				}
			}
			return nil
		}()
		if err != nil {
			return nil, err
		}
		if allFound(fileContents) {
			break
		}
	}
	return fileContents, nil
}

func allFound(content map[string][]byte) bool {
	for _, v := range content {
		if v == nil {
			return false
		}
	}
	return true
}

func ExtractImageFile(ctx context.Context, imageRef string, pullSecret []byte, file string, out io.Writer) error {
	layers, fromBlobs, err := getMetadata(ctx, imageRef, pullSecret)
	if err != nil {
		return err
	}

	// Iterate over layers in reverse order to find the most recent version of files
	found := false
	for i := len(layers) - 1; i >= 0; i-- {
		layer := layers[i]
		err := func() error {
			r, err := fromBlobs.Open(ctx, layer.Digest)
			if err != nil {
				return fmt.Errorf("unable to access the source layer %s: %v", layer.Digest, err)
			}
			defer r.Close()
			rc, err := dockerarchive.DecompressStream(r)
			if err != nil {
				return err
			}
			defer rc.Close()
			tr := tar.NewReader(rc)
			for {
				hdr, err := tr.Next()
				if err != nil {
					if err == io.EOF {
						break
					}
					return err
				}
				if hdr.Typeflag == tar.TypeReg {
					if hdr.Name != file {
						continue
					}
					found = true
					if _, err := io.Copy(out, tr); err != nil {
						return err
					}
					return nil
				}
			}
			return nil
		}()
		if err != nil {
			return err
		}
		if found {
			return nil
		}
	}
	return fmt.Errorf("file not found")
}

func ExtractImageFilesToDir(ctx context.Context, imageRef string, pullSecret []byte, pattern string, outputDir string) error {
	regex, err := regexp.Compile(pattern)
	if err != nil {
		return fmt.Errorf("invalid pattern: %w", err)
	}

	layers, fromBlobs, err := getMetadata(ctx, imageRef, pullSecret)
	if err != nil {
		return err
	}

	// Iterate over layers in reverse order to find the most recent version of files
	written := map[string]struct{}{}
	for i := len(layers) - 1; i >= 0; i-- {
		layer := layers[i]
		err := func() error {
			r, err := fromBlobs.Open(ctx, layer.Digest)
			if err != nil {
				return fmt.Errorf("unable to access the source layer %s: %v", layer.Digest, err)
			}
			defer r.Close()
			rc, err := dockerarchive.DecompressStream(r)
			if err != nil {
				return err
			}
			defer rc.Close()
			tr := tar.NewReader(rc)
			for {
				hdr, err := tr.Next()
				if err != nil {
					if err == io.EOF {
						break
					}
					return err
				}
				if hdr.Typeflag == tar.TypeReg {
					// Only copy the file once from the most recent layer
					if _, exists := written[hdr.Name]; exists {
						continue
					}
					if !regex.MatchString(hdr.Name) {
						continue
					}
					dst := filepath.Join(outputDir, hdr.Name)
					if err := os.MkdirAll(filepath.Clean(filepath.Dir(dst)), 0755); err != nil {
						return fmt.Errorf("failed to make dir: %w", err)
					}
					dstfd, err := os.Create(dst)
					if err != nil {
						return err
					}
					if _, err = io.Copy(dstfd, tr); err != nil {
						dstfd.Close()
						return err
					}
					dstfd.Close()
					written[hdr.Name] = struct{}{}
				}
			}
			return nil
		}()
		if err != nil {
			return err
		}
	}
	return nil
}

func getMetadata(ctx context.Context, imageRef string, pullSecret []byte) ([]distribution.Descriptor, distribution.BlobStore, error) {
	repo, ref, err := GetRepoSetup(ctx, imageRef, pullSecret)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to setup repo to get metadata for image: %s: %w", imageRef, err)
	}
	firstManifest, location, err := manifest.FirstManifest(ctx, ref, repo)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to obtain root manifest for %s: %w", imageRef, err)
	}
	_, layers, err := manifest.ManifestToImageConfig(ctx, firstManifest, repo.Blobs(ctx), location)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to obtain image layers for %s: %w", imageRef, err)
	}
	return layers, repo.Blobs(ctx), nil
}

func GetRepoSetup(ctx context.Context, imageRef string, pullSecret []byte) (distribution.Repository, reference.DockerImageReference, error) {
	rt, err := rest.TransportFor(&rest.Config{})
	if err != nil {
		return nil, reference.DockerImageReference{}, fmt.Errorf("failed to create secure transport: %w", err)
	}
	insecureRT, err := rest.TransportFor(&rest.Config{TLSClientConfig: rest.TLSClientConfig{Insecure: true}})
	if err != nil {
		return nil, reference.DockerImageReference{}, fmt.Errorf("failed to create insecure transport: %w", err)
	}
	credStore, err := dockercredentials.NewFromBytes(pullSecret)
	if err != nil {
		return nil, reference.DockerImageReference{}, fmt.Errorf("failed to parse docker credentials: %w", err)
	}
	registryContext := registryclient.NewContext(rt, insecureRT).WithCredentials(credStore).
		WithRequestModifiers(transport.NewHeaderRequestModifier(http.Header{http.CanonicalHeaderKey("User-Agent"): []string{rest.DefaultKubernetesUserAgent()}}))

	ref, err := reference.Parse(imageRef)
	if err != nil {
		return nil, reference.DockerImageReference{}, fmt.Errorf("failed to parse image reference %q: %w", imageRef, err)
	}
	repo, err := registryContext.Repository(ctx, ref.DockerClientDefaults().RegistryURL(), ref.RepositoryName(), false)
	if err != nil {
		return nil, reference.DockerImageReference{}, fmt.Errorf("failed to create repository client for %s: %w", ref.DockerClientDefaults().RegistryURL(), err)
	}
	return repo, ref, nil
}

func IsMultiArchManifestList(ctx context.Context, imageRef string, pullSecret []byte) (bool, error) {
	repo, ref, err := GetRepoSetup(ctx, imageRef, pullSecret)

	var srcDigest digest.Digest
	if len(ref.ID) > 0 {
		srcDigest = digest.Digest(ref.ID)
	} else if len(ref.Tag) > 0 {
		desc, err := repo.Tags(ctx).Get(ctx, ref.Tag)
		if err != nil {
			return false, err
		}
		srcDigest = desc.Digest
	} else {
		return false, err
	}
	manifests, err := repo.Manifests(ctx)
	if err != nil {
		return false, err
	}
	srcManifest, err := manifests.Get(ctx, srcDigest, manifest.PreferManifestList)
	if err != nil {
		return false, err
	}

	mediaType, payload, err := srcManifest.Payload()
	if err != nil {
		return false, fmt.Errorf("failed to get payload %s: %w", imageRef, err)
	}

	if mediaType == "application/vnd.docker.distribution.manifest.list.v2+json" {
		m := new(manifestlist.DeserializedManifestList)
		err := m.UnmarshalJSON(payload)
		if err != nil {
			return false, fmt.Errorf("failed to unmarshal json %s: %w", imageRef, err)
		}

		count := 0
		for _, arch := range m.ManifestList.Manifests {
			switch arch.Platform.Architecture {
			case "arm64", "amd64", "s390x", "ppc64le":
				count = count + 1
			}
		}

		if count > 1 {
			return true, nil
		} else {
			return false, nil
		}
	} else {
		return false, nil
	}
}

func FindArchManifest(ctx context.Context, imageRef string, pullSecret []byte, osToFind string, archToFind string) (manifestImageRef string, err error) {
	repo, ref, err := GetRepoSetup(ctx, imageRef, pullSecret)
	if err != nil {
		return "", fmt.Errorf("failed to get repo setup when getting manifest for arch: %w", err)
	}

	var srcDigest digest.Digest
	if len(ref.ID) > 0 {
		srcDigest = digest.Digest(ref.ID)
	} else if len(ref.Tag) > 0 {
		desc, err := repo.Tags(ctx).Get(ctx, ref.Tag)
		if err != nil {
			return "", err
		}
		srcDigest = desc.Digest
	} else {
		return "", err
	}
	manifests, err := repo.Manifests(ctx)
	if err != nil {
		return "", err
	}
	manifestList, err := manifests.Get(ctx, srcDigest, manifest.PreferManifestList)
	if err != nil {
		return "", fmt.Errorf("failed to obtain manifest list for %s: %w", imageRef, err)
	}

	_, payload, err := manifestList.Payload()
	if err != nil {
		return "", fmt.Errorf("failed to get manifest payload: %w", err)
	}

	m := new(manifestlist.DeserializedManifestList)
	err = m.UnmarshalJSON(payload)
	if err != nil {
		return "", fmt.Errorf("failed to get unmarshal manifest list: %w", err)
	}

	matchingManifestForArch := imageRef
	for _, manifestDesc := range m.ManifestList.Manifests {
		if osToFind == manifestDesc.Platform.OS && archToFind == manifestDesc.Platform.Architecture {
			splitSHA := strings.Split(imageRef, "@")
			if len(splitSHA) != 2 {
				return "", fmt.Errorf("failed to parse imageRef %s: %w", imageRef, err)
			}

			matchingManifestForArch = splitSHA[0] + "@" + string(manifestDesc.Descriptor.Digest)
			break
		}
	}
	return matchingManifestForArch, nil
}