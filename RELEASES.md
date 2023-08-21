# Release instructions

Releases are performed through Github Action workflows.

- Ensure all changes to be released are in the `main` branch
    - You can do this by opening a PR to merge `dev` -> `main`
- Once PR is merged, ensure you have pulled down the latest `main` branch
    - `git pull origin main`
- Create the new tag (please prepend the tag with "v")
    - `git tag <version>` (ex: `git tag v4.0.0`)
- Push the tag up
    - `git push origin <version>` (ex: `git push origin v4.0.0`)
