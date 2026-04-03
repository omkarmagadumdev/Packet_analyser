# Packet Analyzer React UI

This folder contains a Next.js (React) control plane for the DPI engine in the parent repository. The UI lets you:

- Upload PCAP files
- Configure blocking rules (IP, app, domain, port)
- Configure engine execution (load balancers, fast paths, worker threads, verbose)
- Run DPI analysis through a server API route
- View report output and classification summary
- Download filtered PCAP output (for smaller outputs)

## Local Development

From this folder:

```bash
npm install
npm run dev
```

Then open http://localhost:3000.

## How It Works

- UI page: `src/app/page.js`
- API route: `src/app/api/dpi/process/route.js`
- Engine implementation consumed by API: `../js/src/dpi_engine.js`

The API route writes uploaded files to the OS temp directory, executes the engine, reads filtered output, then returns stats + reports as JSON.

## Vercel Deployment

1. Import this repository in Vercel.
2. Set Root Directory to `web`.
3. Build Command: `npm run build`
4. Output Directory: `.next`
5. Install Command: `npm install`

Recommended runtime notes:

- Keep `use worker threads` disabled in production serverless functions unless you migrate to dedicated compute.
- Large PCAP downloads are not inlined by default to avoid oversized JSON payloads; production should stream to object storage.

## Production Hardening Suggestions

- Add authentication and per-user job isolation.
- Persist outputs and reports in object storage (Vercel Blob, S3, or GCS).
- Add queue-based execution for large captures and long-running jobs.
- Add observability around API duration, failure rate, and payload size.
