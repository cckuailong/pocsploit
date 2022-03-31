import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
from lib.cli import main


if __name__ == "__main__":
    main()