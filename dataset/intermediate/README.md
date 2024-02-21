# Country Specific Datasets

## CISA
- `.gov` dataset from https://github.com/cisagov/dotgov-data
- Commit `dbdf5d90dfd11bbf16144c0e44861d6b1b409919`
- Updated August 26 2023.
- Utilizes `current-full.csv`. Accessed August 27, 2023

## GSA
- US government dataset, excluding `.gov` and `.mil`.
- This list includes the `1_govt_urls_full.csv` from https://github.com/GSA/govt-urls updated on Feb 22 
- Commit `a53b9ea2aad35d1c87575ccfb4a6fc2c30814991`.
- Accessed August 27, 2023

## Know Nepal
- Nepal dataset, utilizes data/websites.json from https://github.com/Know-Nepal/government-websites/
- Updated on April 5th
- Commit `fe9ea1fc74f601f4a0de0559195bb6ec42bdcdfb`.
- Accessed August 27, 2023

## Dotmil
- Utilizes https://github.com/esonderegger/dotmil-domains.
- Direct link: https://raw.githubusercontent.com/esonderegger/dotmil-domains/master/dotmil-domains.csv.
- Updated Jul 9, 2015. 
- Commit `f233b51104499a9ab6dd72927b25ad1506dcbd6d`.
- Accessed Aug 28, 2023

## Gov UK
- Utilizes https://www.gov.uk/government/publications/list-of-gov-uk-domain-names.
- Direct link: https://assets.publishing.service.gov.uk/government/uploads/system/uploads/attachment_data/file/1147893/List_of_gov.uk_domains_as_of_30_March_2023.csv.
- Accessed Aug 28, 2023

## Army.mil
- Utilizes https://www.army.mil/a-z/.
- HTML is directly retrieved, and parsed for URLS.
- Accessed Aug 28, 2023

# General Country Datasets

## Crux
- Chrome UX report, utilizes `data/global/current.csv.gz` retrieved from https://github.com/zakird/crux-top-lists 
- Updated on Aug 9th
- Commit `1395fe9af3cfe7270194f3bdf7db20785417f587`.
- Accessed Aug 27, 2023

## Govcookies

> Matthias Gotze, Srdjan Matic, Costas Iordanou, Georgios Smaragdakis, and Nikolaos Laoutaris. 2022. Measuring Web Cookies in Governmental Websites. In Proceedings of the 14th ACM Web Science Conference 2022 (WebSci '22). Association for Computing Machinery, New York, NY, USA, 44–54. https://doi.org/10.1145/3501247.3531545

- Utilizes https://govcookies.github.io/G20.urls
- Linked on https://govcookies.github.io/
- Accessed Aug 27, 2023

## Majestic Million
- Retrieved from https://majestic.com/reports/majestic-million.
- Direct link: https://downloads.majestic.com/majestic_million.csv.
- Accessed August 27, 2023

## Tranco
- Retrieved from https://tranco-list.eu/
- link: https://tranco-list.eu/download/LY9Z4/full. Utilizing FULL list.
- Accessed August 27, 2023

## Cisco Umbrella
- Retrieved from https://s3-us-west-1.amazonaws.com/umbrella-static/index.html.
- Direct link: http://s3-us-west-1.amazonaws.com/umbrella-static/top-1m.csv.zip.
- Accessed August 27, 2023

## GovHTTPS-Data
- This list includes the dataset.csv from https://github.com/uw-ictd/GovHTTPS-Data 
- Updated on Aug 7, 2022 
- Commit `abd5379a3f13bbd42a812942d7f48a9f00deb728`.
- Accessed August 27, 2023

## Built with
- This list utilizes the built with top 1 million domain list: https://builtwith.com/top-1m.
- Direct link: https://builtwith.com/dl/builtwith-top1m.zip.
- Accessed Aug 27, 2023

## Domcop
- This list utilizes the domcom top 10 million domain list: https://www.domcop.com/top-10-million-websites. 
- Direct link: https://www.domcop.com/files/top/top10milliondomains.csv.zip.
- Accessed Aug 27, 2023

## Cloudflare Radar
- This list utilizes the top 1 million domain list from cloudflare: https://radar.cloudflare.com/domains.
- Direct link: https://radar.cloudflare.com/charts/LargerTopDomainsTable/attachment?id=639&top=1000000&startDate=2023-08-14&endDate=2023-08-21.
- Accessed Aug 27, 2023

## Alexa
- This list utilizes the top 1 million domain list from Alexa: http://s3.amazonaws.com/alexa-static/top-1m.csv.zip.  Since this was discontinued by Amazon, we use the internet wayback machine to access the list. 
- The list was last accessible August 3rd of 2023, which is the version we use. 
- The list itself was updated February 1, 2023.
- Direct link: http://web.archive.org/web/20230803120013/http://s3.amazonaws.com/alexa-static/top-1m.csv.zip.
- Accessed Aug 28, 2023

## Et Tu, brute? WWW '22

> Nayanamana Samarasinghe, Aashish Adhikari, Mohammad Mannan, and Amr Youssef. 2022. Et tu, Brute? Privacy Analysis of Government Websites and Mobile Apps. In Proceedings of the ACM Web Conference 2022 (WWW '22). Association for Computing Machinery, New York, NY, USA, 564–575. https://doi.org/10.1145/3485447.3512223

Utilizes a list of ~220k government websites utilized in the 2022 paper "Privacy Analysis of Government Websites and Mobile Apps".

- We utilize the files under dataset/govt_websites in the repo: https://github.com/nayanamana/et_tu_brute_thewebconf_22.
- Commit `36e276ce0b95f8d66b3a34bb084b5ba0dd4629a6` on Jun 24, 2022.
- Accessed Aug 29, 2023 

## GovHTTPS

> Sudheesh Singanamalla, Esther Han Beol Jang, Richard Anderson, Tadayoshi Kohno, and Kurtis Heimerl. 2020.
Accept the Risk and Continue: Measuring the Long Tail of Government https Adoption. In ACM Internet
Measurement Conference (IMC ’20), October 27–29, 2020, Virtual Event, USA. ACM, New York, NY, USA,
21 pages. https://doi.org/10.1145/3419394.3423645

- Direct link: https://github.com/uw-ictd/GovHTTPS-Data
- 