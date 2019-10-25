# dohdns
A utility to query DNS records using DNS over HTTPS public servers provided by Google and Cloudflare.

To install run

```
$ cargo install --path .
```

And to run you can do the following:

```
$ dohdns mx gmail.com
+------------+------+------+-------------------------------------+
|    Name    | Type | TTL  |                Data                 |
+------------+------+------+-------------------------------------+
| gmail.com. |   MX | 3599 | 40 alt4.gmail-smtp-in.l.google.com. |
+------------+------+------+-------------------------------------+
| gmail.com. |   MX | 3599 | 20 alt2.gmail-smtp-in.l.google.com. |
+------------+------+------+-------------------------------------+
| gmail.com. |   MX | 3599 | 5 gmail-smtp-in.l.google.com.       |
+------------+------+------+-------------------------------------+
| gmail.com. |   MX | 3599 | 10 alt1.gmail-smtp-in.l.google.com. |
+------------+------+------+-------------------------------------+
| gmail.com. |   MX | 3599 | 30 alt3.gmail-smtp-in.l.google.com. |
+------------+------+------+-------------------------------------+

$ dohdns a www.cloudflare.com
+---------------------+------+-----+--------------+
|        Name         | Type | TTL |     Data     |
+---------------------+------+-----+--------------+
| www.cloudflare.com. |    A | 296 | 104.17.210.9 |
+---------------------+------+-----+--------------+
| www.cloudflare.com. |    A | 296 | 104.17.209.9 |
+---------------------+------+-----+--------------+
```