import sys

from app.pipeline import run_pipeline, print_terminal_report


def main() -> None:
    print("=" * 72)
    print("SIH26155 - Multi-Vendor Network Security Compliance Auditor")
    print("Member 2 Local Prototype")
    print("=" * 72)

    path = (sys.argv[1] if len(sys.argv) > 1 else input("Enter configuration file path: ")).strip().strip('"')

    if not path:
        print("ERROR: No configuration file path supplied.")
        raise SystemExit(1)

    try:
        result = run_pipeline(path)
        print_terminal_report(result)
    except Exception as exc:
        print(f"ERROR: {exc}")
        raise SystemExit(1)


if __name__ == "__main__":
    main()
