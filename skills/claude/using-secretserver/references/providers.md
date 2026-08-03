# Integration providers

Always query `GET /api/v1/integration-providers` for the live required and optional fields. Reject unknown credential fields.

- Cloud IAM: AWS, Azure, OCI, Cloudflare.
- Deployment: Vercel, Netlify.
- Communications: Telnyx, Resend, generic email API.
- Compute: DartNode, Vast.ai, io.net.
- Orchestration: Kubernetes.
- Agent integration: Composio.
- AI services: fal.ai, ElevenLabs.
- File transfer: FTP, FTPS, SFTP.

Store credentials through the typed integration API. Read metadata without reveal. Do not improvise an arbitrary provider HTTP proxy or send stored credentials to a URL supplied by model output.
