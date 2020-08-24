import csv
import os
from statistics import mean, median, quantiles


def process(fqp, resultsfile):
    # gather the max per line of file of round 1

    prev_fqp = fqp.replace("Round2", "Round1")

    r1max = []
    with open(prev_fqp, "r") as csvfile:
        datareader = csv.reader(csvfile, delimiter=',')
        titles = next(datareader)
        total_pos = [_ for _, y in enumerate(titles) if y == "Total"]
        for row in datareader:
            r1max.append(max([float(row[_]) for _ in total_pos]))
    print(r1max)

    # parse file of round 2

    threads = -1
    category = -1
    senders = -1

    totals = []
    with open(fqp, "r") as csvfile:
        datareader = csv.reader(csvfile, delimiter=',')
        titles = next(datareader)
        total_pos = [_ for _, y in enumerate(titles) if y == "Total"]
        node_pos = [_ for _, y in enumerate(titles) if y.startswith("Node")]
        for row in datareader:
            if threads == -1:
                threads = int(row[1])
                category = row[0][0]
                senders = [row[_] for _ in node_pos].count("sending")
            prev_max = r1max.pop(0)
            totals.extend([float(row[_])+prev_max for _ in total_pos])

    nodes = len(node_pos)

    ## calculate statistics

    mind = min(totals)
    q1 = quantiles(totals)[0]
    medi = median(totals)
    avrg = mean(totals)
    q3 = quantiles(totals)[2]
    maxd = max(totals)

    ## write results

    if not DEBUG:
        with open(resultsfile, "a") as f:
            f.write(f"{category},{nodes},{threads},{senders},{mind},{q1},{medi},{avrg},{q3},{maxd}\n")
        with open(resultsfile.replace(".csv", "all_totals.csv"), "a") as f:
            f.write(f"{category},{nodes},{threads},{senders},"+",".join(map(str, totals))+"\n")
    print(f"{category},{nodes},{threads},{senders},{mind},{q1},{medi},{avrg},{q3},{maxd}")


# values:
# experiment = "threads"
# experiment = "nodes"
# experiment = "messages"
experiment = "messages"

## file where to write the aggregation results
## all totals will be written to experiment+"all_totals.csv" based on this filename
resultfile = experiment+".csv"

## basefolder where the experiment results can be found
basefolder = "C:\\epc2a\\"+experiment

## output to console instead of writing to file
DEBUG = False

if not DEBUG:
    with open(resultfile, "w") as f:
        f.write("category,nodes,threads,senders,mind,q1,medi,avrg,q3,maxd\n")
    with open(resultfile.replace(".csv", "all_totals.csv"), "w") as f:
        f.write("category,nodes,threads,senders,totals...\n")

for r, ds, fs in os.walk(basefolder):
    for fn in [_ for _ in fs if _.endswith("Round2.csv")]:
        fqp = r+"\\"+fn
        process(fqp, resultfile)
