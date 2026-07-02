import sys

BANNER = """\
================================================================
  reconai -- automated recon toolkit for AUTHORIZED testing only
  Only run this against targets you own or have explicit written
  permission to test (bug bounty scope, pentest engagement, lab).
  Unauthorized scanning may be illegal in your jurisdiction.
================================================================
"""


def show_and_confirm(assume_yes: bool) -> bool:
    print(BANNER)
    if assume_yes:
        return True
    if not sys.stdin.isatty():
        # Non-interactive context without --yes: don't scan silently.
        print("Refusing to proceed without --yes in a non-interactive session.")
        return False
    answer = input("Confirm you are authorized to scan this target [y/N]: ").strip().lower()
    return answer in ("y", "yes")
