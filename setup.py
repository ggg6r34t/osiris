from setuptools import setup, find_packages

setup(
    name='osiris',
    version='1.0.0',
    description='A powerful OSINT CLI tool for investigating trademark violations, people, scams, phishing, and more.',
    author='ggg6r43t',
    author_email='ghyorka@proton.me',
    url='https://github.com/ggg6r34t/osiris',
    package_dir={"": "src"},
    packages=find_packages(where="src", include=["osiris", "osiris.*"]),
    include_package_data=True,
    install_requires=[
        'rich>=14.0.0',
        'requests>=2.32.3',
        'fuzzywuzzy>=0.18.0',
        'pyfiglet>=1.0.2',
        'python-dotenv>=1.0.0',
        'python-Levenshtein>=0.20.0',
        'beautifulsoup4>=4.12.3',
        'python-whois>=0.7.3',
        'dnspython>=2.7.0',
        'ipwhois>=1.1.0',
        'pyopenssl>=25.1.0',
        'python-dateutil>=2.9.0',
        'dnstwist>=20250130',
        'pysocks>=1.7.1'
    ],
    entry_points={
        'console_scripts': [
            'osiris=osiris.cli:main',
        ],
    },
    classifiers=[
        'Programming Language :: Python :: 3',
        'Operating System :: OS Independent',
    ],
    python_requires='>=3.9',
)
