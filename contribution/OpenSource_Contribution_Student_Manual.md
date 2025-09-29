
# Open Source Contribution Student Manual

This manual is designed to guide students through every step of contributing to open source projects. It covers how to choose projects, evaluate repositories, understand contribution flows, and execute contributions with examples and code snippets.

---

## 1. What to Work On

Open source projects are everywhere. As a beginner:
- Start small: documentation updates, bug fixes, or adding examples.
- Look for repositories tagged as **“good first issue”** or **“help wanted”**.
- Consider topics that align with your studies or interests.

**Examples of beginner-friendly repositories:**
- [First Contributions](https://github.com/firstcontributions/first-contributions)
- [Public APIs List](https://github.com/public-apis/public-apis)
- [FreeCodeCamp](https://github.com/freeCodeCamp/freeCodeCamp)

---

## 2. Evaluate a Repo in 5 Minutes

When you open a GitHub repository, check these:
- **README.md**: Does it clearly explain the project?
- **Issues Tab**: Are there beginner-friendly issues (e.g. “good first issue”)?
- **Last Commit**: Is the repo actively maintained?
- **Contributing Guidelines**: Look for a `CONTRIBUTING.md` file.

If a repo has all these, it’s likely a good candidate to contribute to.

---

## 3. Standard Contribution Flow

Here’s the high-level flow for contributing to most open source projects:
1. Fork the repository.
2. Clone your fork locally.
3. Create a new branch for your change.
4. Make changes locally.
5. Commit and push changes to your fork.
6. Open a Pull Request (PR) to the original repository.

---

## 4. Step-by-Step Contribution Guide

### Step 1: Fork the Repository
Click the **Fork** button at the top-right of the repo page.

### Step 2: Clone the Fork
```bash
git clone https://github.com/YOUR-USERNAME/REPO-NAME.git
cd REPO-NAME
```

### Step 3: Add the Original Repository as a Remote
```bash
git remote add upstream https://github.com/ORIGINAL-OWNER/REPO-NAME.git
```

### Step 4: Create a Branch
```bash
git checkout -b your-branch-name
```

### Step 5: Make Changes
Edit code, documentation, or files as required.

Track your changes:
```bash
git status
git add .
git commit -m "Describe your changes here"
```

### Step 6: Push Changes to Your Fork
```bash
git push origin your-branch-name
```

### Step 7: Open a Pull Request
Go to your fork on GitHub and click **“Compare & Pull Request”**.

---

## 5. Minimal Git Commands Cheat Sheet

| Action                     | Command                                   |
|----------------------------|-------------------------------------------|
| Clone a repository         | `git clone URL`                          |
| Create a branch            | `git checkout -b branch-name`             |
| Stage changes              | `git add .`                              |
| Commit changes             | `git commit -m "message"`                 |
| Push to fork               | `git push origin branch-name`             |
| Sync with upstream         | `git fetch upstream` <br> `git merge upstream/main` |
| View status                | `git status`                             |

---

## 6. Submission Checklist

Before submitting your PR, ensure:
- [ ] Code follows the project’s style guide.
- [ ] Tests (if applicable) pass locally.
- [ ] Documentation is updated if needed.
- [ ] Commit messages are clear.
- [ ] PR description explains changes and references issues.

---

## 7. Where to Find Open Source Projects

- **GitHub Explore:** [https://github.com/explore](https://github.com/explore)
- **Open Source Friday:** [https://opensourcefriday.com/](https://opensourcefriday.com/)
- **First Contributions:** [https://github.com/firstcontributions/first-contributions](https://github.com/firstcontributions/first-contributions)
- **Up for Grabs:** [https://up-for-grabs.net/](https://up-for-grabs.net/)

---

## 8. High-Level Flow Summary

1. **Find a project** (use GitHub search or curated lists).
2. **Evaluate the repo** (README, Issues, last commit).
3. **Fork & clone** the repository.
4. **Create a branch** for your work.
5. **Make changes** locally.
6. **Push changes** to your fork.
7. **Open a PR** to the original repo.
8. **Engage with maintainers** for feedback.

---

This manual can be used by educators to guide students step-by-step through their first open source contributions.
