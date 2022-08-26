import setuptools
import subprocess
import os

sta_awscli_version = (
    subprocess.run(["git", "describe", "--tags"], stdout=subprocess.PIPE)
    .stdout.decode("utf-8")
    .strip()
)

if "-" in sta_awscli_version:
    # when not on tag, git describe outputs: "1.3.3-22-gdf81228"
    # pip has gotten strict with version numbers
    # so change it to: "1.3.3+22.git.gdf81228"
    # See: https://peps.python.org/pep-0440/#local-version-segments
    v,i,s = sta_awscli_version.split("-")
    sta_awscli_version = v + "+" + i + ".git." + s

assert "-" not in sta_awscli_version
assert "." in sta_awscli_version

assert os.path.isfile("sta-awscli/version.py")
with open("sta-awscli/VERSION", "w", encoding="utf-8") as fh:
    fh.write("%s\n" % sta_awscli_version)

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setuptools.setup(
    name="sta-awscli",
    version=sta_awscli_version,
    author="Gur Talmor, Cina Shaykhian and Alex Basin",
    author_email="",
    description="MFA for AWS CLI using SafeNet Trusted Access (STA)",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/thalesdemo/sta-awscli",
    packages=setuptools.find_packages(),
    package_data={"sta-awscli"},
    include_package_data=True,
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: GNU General Public License v3 (GPLv3)",
        "Operating System :: OS Independent",
    ],
    python_requires=">=3.5",
    entry_points={},
    install_requires=[
        "requests >= 2.25.1",
        "beautifulsoup4",
        "boto3",
        "opencv-python",
        "validators",
        "pytesseract",
        "urllib3",
        "pwinput",
        "python-dateutil",
    ],
)
