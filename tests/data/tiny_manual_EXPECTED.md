# tiny_manual.csv: expected result worked out by hand

`tiny_manual.csv` is **hand-written test data**, not real CTU-13 traffic. It uses
the CTU-13 column layout so that it exercises the same code. Thresholds come from
`tiny_config.json`: fan-out >= 3 destination IPs, large upload >= 2000 bytes.

## Step 1: which rows are kept (10 data rows)

| Row | SrcAddr | DstAddr | Dport | TotBytes | SrcBytes | Label | Kept? |
|---|---|---|---|---|---|---|---|
| 1 | 10.0.0.1 | 10.0.0.100 | 80 | 100 | 60 | From-Botnet | yes |
| 2 | 10.0.0.2 | 10.0.0.100 | 80 | 5000 | 1500 | From-Normal | yes |
| 3 | 10.0.0.1 | 10.0.0.101 | 80 | 200 | 120 | From-Botnet | yes |
| 4 | 10.0.0.1 | 10.0.0.102 | 443 | 300 | 180 | From-Botnet | yes |
| 5 | 10.0.0.2 | 10.0.0.100 | 80 | 3000 | 900 | From-Normal | yes |
| 6 | 10.0.0.1 | 10.0.0.100 | 53 | 400 | 240 | From-Botnet | yes |
| 7 | 10.0.0.3 | 10.0.0.1 | 0x0008 = 8 | 98 | 98 | Background | yes (hex port) |
| 8 | 10.0.0.4 | 10.0.0.1 | 6667 | 50 | 30 | **To**-Botnet | yes |
| 9 | 10.0.0.1 | 10.0.0.103 | 80 | **abc** | 60 | From-Botnet | **no**: TotBytes is not a number |
| 10 | *(empty)* | 10.0.0.104 | 80 | 100 | 60 | Background | **no**: empty SrcAddr |

Rows read 10, kept 8, skipped 2 (1 "TotBytes is not a number", 1 "empty SrcAddr").

## Step 2: numbers per source IP

| IP | flows | TotBytes | SrcBytes | distinct DstAddr | distinct Dport | gaps between flows |
|---|---|---|---|---|---|---|
| 10.0.0.1 | rows 1,3,4,6 = 4 | 100+200+300+400 = 1000 | 60+120+180+240 = 600 | .100, .101, .102 = 3 | 80, 443, 53 = 3 | 10 s, 10 s, 10 s: mean 10, std 0 |
| 10.0.0.2 | rows 2,5 = 2 | 5000+3000 = 8000 | 1500+900 = 2400 | .100 = 1 | 80 = 1 | 20 s: mean 20, std 0 |
| 10.0.0.3 | 1 | 98 | 98 | 1 | 1 | only 1 flow: none |
| 10.0.0.4 | 1 | 50 | 30 | 1 | 1 | only 1 flow: none |

Note: row 9 would have given 10.0.0.1 a 4th destination (10.0.0.103). Because the row is
skipped, the correct answer is 3.

## Step 3: rules

- Fan-out (>= 3): 10.0.0.1 has exactly 3, and the rule uses >=, so it **is flagged**. Others have 1.
- Large upload (>= 2000): 10.0.0.2 sent 2400, **flagged**. 10.0.0.1 sent 600, not flagged.

## Step 4: comparison with labels

- Bot IPs (at least one From-Botnet flow as source): only 10.0.0.1. 10.0.0.4 is **not** a bot:
  its label is To-Botnet, meaning the bot is the destination.
- Labelled-normal IPs: 10.0.0.2.
- Bots flagged 1 of 1, missed 0, labelled-normal IPs flagged 1 (a false alarm), background flagged 0.

## Expected report.csv (order: most destinations first)

```
10.0.0.1, fanout,       n_dst_ips=3 >= 3,       label bot
10.0.0.2, large_upload, src_bytes=2400 >= 2000, label normal
```

`tests/test_manual_expected.py` checks that the program gives exactly these numbers.
