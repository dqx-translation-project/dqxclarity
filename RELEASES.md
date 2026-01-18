# Release instructions

Releases are performed through Github Action workflows.

- All changes expected to be released should exist in `main`
- Ensure you have pulled down the latest `main` branch
    - `git pull origin main`
- Create a new tag (make sure to prepend the tag with "v")
    - `git tag <version>` (ex: `git tag v4.0.0`)
- Push the tag up
    - `git push origin <version>` (ex: `git push origin v4.0.0`)
- This will trigger a Github Action named `build-release-zip`
- After a minute or two, you'll see a new release generated with the tag that was pushed up
