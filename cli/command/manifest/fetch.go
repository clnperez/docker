package manifest

func getImageData(dockerCli *command.DockerCli, name string, transactionID string, fetchOnly bool) ([]ImgManifestInspect, *registry.RepositoryInfo, error) {

	var (
		lastErr                    error
		discardNoSupportErrors     bool
		foundImages                []ImgManifestInspect
		confirmedV2                bool
		confirmedTLSRegistries     = make(map[string]struct{})
		namedRef, transactionNamed reference.Named
		err                        error
		normalName                 string
	)

	if namedRef, err = reference.ParseNormalizedNamed(name); err != nil {
		return nil, nil, fmt.Errorf("Error parsing reference for %s: %s\n", name, err)
	}
	if transactionID != "" {
		if transactionNamed, err = reference.ParseNormalizedNamed(transactionID); err != nil {
			return nil, nil, fmt.Errorf("Error parsing reference for %s: %s\n", transactionID, err)
		}
		if _, isDigested := transactionNamed.(reference.Canonical); !isDigested {
			transactionNamed = reference.TagNameOnly(transactionNamed)
		}
		transactionID = makeFilesafeName(transactionNamed.String())
	}

	// Make sure these have a tag, as long as it's not a digest
	if _, isDigested := namedRef.(reference.Canonical); !isDigested {
		namedRef = reference.TagNameOnly(namedRef)
	}
	normalName = namedRef.String()
	logrus.Debugf("getting image data for ref: %s", normalName)

	// Resolve the Repository name from fqn to RepositoryInfo
	// This calls TrimNamed, which removes the tag, so always use namedRef for the image.
	repoInfo, err := registry.ParseRepositoryInfo(namedRef)
	if err != nil {
		return nil, nil, err
	}

	// First check to see if stored locally, either a single manfiest or list:
	if !fetchOnly {
		logrus.Debugf("Checking locally for %s", normalName)
		foundImages, err = loadManifest(makeFilesafeName(normalName), transactionID)
		if err != nil {
			return nil, nil, err
		}
	}
	// Great, no reason to pull from the registry.
	if len(foundImages) > 0 {
		return foundImages, repoInfo, nil
	}

	images, err := distribution.Fetch(ctx, repoInfo)
}
