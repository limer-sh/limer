wrk.method = "POST"
wrk.body   = '{"type":"order","customer":{"id":"c-12345"},"items":[{"sku":"A1","qty":2},{"sku":"B2","qty":1}],"total":42.5}'
wrk.headers["Content-Type"] = "application/json"
