package daemon // import "github.com/docker/docker/daemon"

import (
	"context"

	"github.com/docker/distribution/reference"
	"github.com/docker/docker/errdefs"
	"github.com/pkg/errors"
)

// The image reference inside a container config or a container object may just
// be an ID.  We have to look it up in the image service to see what image it
// maps to, first
func (daemon *Daemon) verifyImageSigned(image string) error {
	if daemon.trustService == nil {
		return nil
	}
	inspectInfo, err := daemon.imageService.LookupImage(image)
	if err != nil {
		return err
	}
	// do any of the digests validate?
	for _, digestString := range inspectInfo.RepoDigests {
		// get the normalized name, which includes the docker.io prefix if needed
		normalized, err := reference.ParseNormalizedNamed(digestString)
		if err != nil {
			continue
		}
		// get the digest, which MUST be there
		ref, err := reference.Parse(digestString)
		if err != nil {
			continue
		}
		digested, ok := ref.(reference.Canonical)
		if !ok {
			continue
		}
		// Produce a reference with a normalized name and the digest
		digested, err = reference.WithDigest(normalized, digested.Digest())
		if err != nil {
			continue
		}

		if _, err = daemon.trustService.VerifyImageSigned(context.Background(), digested, nil, nil); err == nil {
			return nil // yay, at least one signed
		}
	}
	return errdefs.Forbidden(
		errors.Errorf("could not find trust signature for local image %s", image))
}
