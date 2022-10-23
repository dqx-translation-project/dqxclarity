## Releasing

GitHub contributors have the ability to move code to the `weblate` branch, which is our `stable`.

## How to release

tl;dr:

- Make a new PR with dev as `source` and `weblate` as target
- Put "release: <version>" as the PR title
- Merge

## How to release (detailed)?

We use Github Actions to release code into `weblate`.

Committing changes to the `dev` branch will kick off a build that composes a `dqxclarity.zip` file for consumption. This is a dev release that is not yet available to the public. This is created as a pre-release build and although anyone can download these, no support will be offered.

When we're ready to move changes to the public, a pull request (PR) should be submitted FROM the `dev` branch TO the `weblate` branch. If you don't plan on making a full-blown release, merge the PR and your files will be in the `weblate` branch. This is usually done to update the `glossary.csv` or `json` files.

If you DO plan on making a full-blown release, the title of the PR should be called `release: <version>`. Ensure it starts with the word "release", or a release will not be generated.

Once the builds pass, a new release will be created that increments to the next feature version.

On top of that, a new PR will open to merge the `weblate` changes back down to `dev`. Please merge this PR **RIGHT AFTER** you've done the release.
