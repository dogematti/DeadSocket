# DeadSocket Examples

These examples are copy/paste ready and use explicit flags. Replace targets with hosts you own or have permission to test.

## HTTP GET (concurrency + duration)
```bash
python deadsocket.py \
  --test_type http \
  --target_host https://example.com \
  --duration 30 \
  --concurrency 50 \
  --method GET \
  --timeout 10
```

## HTTP POST (payload + headers)
```bash
python deadsocket.py \
  --test_type http \
  --target_host https://api.example.com/data \
  --num_requests 200 \
  --concurrency 20 \
  --method POST \
  --payload '{"key":"value"}' \
  --headers 'Content-Type:application/json;X-Env:staging' \
  --timeout 10
```

## HTTP without keep-alive (new connection per request)
```bash
python deadsocket.py \
  --test_type http \
  --target_host https://example.com \
  --num_requests 100 \
  --concurrency 10 \
  --method GET \
  --no_keep_alive \
  --timeout 10
```

## RUDY slow POST (hold connections open)
```bash
python deadsocket.py \
  --test_type rudy \
  --target_host https://example.com/upload \
  --num_requests 40 \
  --concurrency 10 \
  --rudy_body_size 1048576 \
  --rudy_chunk_size 10 \
  --rudy_delay 0.5 \
  --timeout 120
```

## Target list (HTTP)
Create `targets.txt` (one per line):
```text
https://example.com
https://example.org
https://example.net
```

Run:
```bash
python deadsocket.py \
  --test_type http \
  --target_host https://example.com \
  --target_list targets.txt \
  --duration 30 \
  --concurrency 30 \
  --method GET \
  --timeout 10
```

## TCP connection test
```bash
python deadsocket.py \
  --test_type tcp \
  --target_host 192.168.1.10 \
  --target_port 8080 \
  --num_requests 500 \
  --concurrency 50
```

## UDP packet test
```bash
python deadsocket.py \
  --test_type udp \
  --target_host 192.168.1.10 \
  --target_port 1234 \
  --num_requests 1000 \
  --concurrency 50
```

## ICMP echo test (requires sudo)
```bash
sudo python deadsocket.py \
  --test_type icmp \
  --target_host 8.8.8.8 \
  --num_requests 10
```

## SYN flood (requires sudo)
```bash
sudo python deadsocket.py \
  --test_type syn \
  --target_host 192.168.1.10 \
  --target_port 80 \
  --num_requests 500
```

## JSON report output
```bash
python deadsocket.py \
  --test_type http \
  --target_host https://example.com \
  --duration 20 \
  --concurrency 25 \
  --method GET \
  --timeout 10 \
  --output_format json \
  --output_file report.json
```
