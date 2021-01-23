# privacy

just a few notes on privacy, as usual, I am no expert

## github

github's default settings put your email in the commit info which can be viewed with `git log`, in the event that you want to clear the git log, you can do that with creating a new branch and deleting the old one

be sure to use `git config` to alter the global email variable prior to committing to the new branch. also, see [this article](https://docs.github.com/en/github/setting-up-and-managing-your-github-user-account/setting-your-commit-email-address) from github on additional measures that can be taken for github and privacy.

```
git checkout --orphan clean
git add -A
git commit -a -m initial
git branch -D main
git branch -m main
git push -f origin main
git gc
```
