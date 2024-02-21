# Parallel Scans using an Orchestrator

This is an example of an orchestrator using the `bin/scan` tool generated from the `make` command. 
The implementation of this orchestrator takes the following arguments to prepare scan commands.

The design of the tool is made flexible to integrate into any orchestor or existing pipelines used.

| **Argument**  | **Description**                                                                    | **Default**                                                                                                                                                            |
| ---------------   	| ------------------------------------------------------------------------------------   	| ------------------------------------------------------------------------------------------------------------------------------------------------------------------------ 	|
|-------------------	|----------------------------------------------------------------------------------------	|--------------------------------------------------------------------------------------------------------------------------------------------------------------------------	|
| `-input`          	| The path to the input file (CSV/TXT)                                                   	| Required. eg. `input/dataset.csv`                                                                                                                                        	|
| `-output`         	| The path to the output directory                                                       	| Required. eg. Creates the output directory if does not exist. Defaults to output directory of the scan tool if not provided                                              	|
| `-type`           	| The type of scan to perform, supported options are one of `{ dns, mail, tls}`          	| Required.                                                                                                                                                                	|
| `-shardsize`      	| Size of the number of entries to scan in a batch, requires an integer                  	| 50000                                                                                                                                                                    	|
| `-batchstart`     	| The index of the batch to begin processing from                                        	| 0                                                                                                                                                                        	|
| `-seed`           	| A randomness seed provided for the scanner to determine shuffling order of entries     	| This is not cryptographic. If no seed is provided, the shuffles will be random during each execution. Do not re-use seed for repeated scans.                             	|
| `-workers`        	| The number of workers to run to perform the scans                                      	| The default is set at 400, reduce or increase the numbers depending on how I/O intensive the scan tasks are. For example, DNS can have higher worker values than mail.   	|
| `-urlcol`         	| The column to read in a given CSV file containing the queries                          	| For CSV files containing multiple columns, the index to the query columns must be provided.                                                                              	|
| `-outcol`         	| The column to read in a given CSV file used in output directory formatting             	| For CSV files containing multiple columns, the index to the query columns must be provided.                                                                              	|
| `-querytype`      	| The DNS QueryType string eg. `{A, AAAA, MX, NS, .... }`                                	| Default is `A` for IPv4 information. This parameter is required only for `-type dns` scans and is not respected for `tls` and `mail` scans.                              	|
| `-slowstart`      	| Whether to slow start mail scans for MX caching (use for accurately cached MX records) 	| By default, this value is false.                                                                                                                                         	|
| `-slowuntil`      	| The number of cached MX records until the slow start is complete                       	| The default is set to 20 (increase for more accurately cached records)                                                                                                   	|
| `-slowbatchsize`  	| The batch sizes of mail scans when conducting a slow start                             	| The default is set to 20 (reduce for more accurately cached records)                                                                                                     	|
| `-nodate`         	| Whether the output files will be contained by a directory denoting the date            	| By default, this value is false.                                                                                                                                         	|
| `-noserver`       	| Whether the cache & IP block list server will be used                                  	| By default, this value is false.                                                                                                                                         	|
| `-h`              	| Displays the content of the various arguments and their defaults                       	|                                                                                                                                                                          	|

> **Note**
> For storage constraints, the resulting JSON files from the scanner are always stored in compressed JSON format.

## Scan Execution When Given a List 

An example execution for the given input list `input/dataset.csv`

```csv
google.com
facebook.com
microsoft.com
twitter.com
apple.com
```

```shell
$ python orchestrator/main.py -input input/dataset.csv -output results -type dns -urlcol 0 -querytype A
```

The execution of the above command from the root directory of the project will result in the following result directory:

```log
results/
  |
  |--YYYY-MM-DD/
    |--dns/
      |--google.com.json
      |--facebook.com.json
```

## Including additional indices in output results

It is possible to use an additional column from the CSV file to index the results into, For example, the changes to `input/dataset.csv` resulting in the following file:

```csv
google.com,Web
facebook.com,Web
microsoft.com,Hardware
twitter.com,Web
apple.com,Hardware
```

When using the `-outcol` as `1` (2nd column), the result structure would be indexed as `results/YYYY-MM-DD/dns/{Web|Hardware}/{hostname}.json`
