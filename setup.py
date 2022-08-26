import setuptools

PACKAGE_NAME = 'sta-awscli'
VERSION = 'v2.0.0'

setuptools.setup(
    name=PACKAGE_NAME,
    packages=[PACKAGE_NAME],
    version=VERSION,
    python_requires='>=3',
    description='MFA for AWS CLI using SafeNet Trusted Access (STA)',
    classifiers=[
        'Development Status :: 4 - Beta',
        'Environment :: Console',
        'License :: OSI Approved :: MIT License',
        'Programming Language :: Python :: 3.5',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3 :: Only',
        'Topic :: Security',
        'Topic :: System :: Systems Administration :: Authentication/Directory'
    ],
    keywords='sta aws cli',
    author='Gur Talmor, Cina Shaykhian and Alex Basin',
    author_email='',
    url='https://github.com/thalesdemo/sta-awscli',
    download_url=(
            'https://github.com/thalesdemo/sta-awscli/archive/refs/tags' +
            VERSION +
            '.tar.gz'
    ),
    py_modules=[PACKAGE_NAME],
    install_requires=[
        'boto3',
        'pytesseract',
        'keyring',
        'requests',
        'beautifulsoup4',
        'urllib3',
        'validators',
        'opencv-python',
        'pwinput',
        'python-dateutil',
    ],
    setup_requires=['nose>=1.0'],
    entry_points={
        "console_scripts": [
            "sta-awscli = {pkg}.cli:login".format(pkg=PACKAGE_NAME)
        ]
    },
    license='MIT License',
    test_suite='nose.collector',
    tests_require=['coverage', 'nose', 'nose-cover3'],
    zip_safe=False,
)
