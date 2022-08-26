from distutils.core import setup

setup(
    name = 'sta-awscli',
    packages = ['sta-awscli'],
    version = '2.0.0',  # Ideally should be same as your GitHub release tag varsion
    description = 'MFA for AWS CLI using SafeNet Trusted Access (STA)',
    author = 'Gur Talmor, Cina Shaykhian and Alex Basin',
    author_email = '',
    url = 'https://github.com/thalesdemo/sta-awscli',
    download_url = 'https://github.com/thalesdemo/sta-awscli/archive/refs/tags/v2.0.0.tar.gz',
    keywords = ['STA', 'AWS', 'MFA', 'awscli', 'SafeNet Trusted Access', 'Thales'],
    classifiers = [],
)
