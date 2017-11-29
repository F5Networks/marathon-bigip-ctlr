# Code Review Guidelines

When doing code reviews, here are some things to be considered.
* Normal design/code quality/style things
* Do any changes need to be reflected in docs?
* Were the appropriate system tests run?
* Do the appropriate unit tests exist?
* Is this a backwards-compatible change; Which branches should it go into?

# Python Development Guidelines
* Unit test all public interfaces
* Format code according to the [PEP8 standard](https://www.python.org/dev/peps/pep-0008).
* Code format is enforced in the build using [flake8](http://flake8.pycqa.org/en/latest/) and [pylint](https://www.pylint.org/), the format check can be executed manually via `make python-lint`
