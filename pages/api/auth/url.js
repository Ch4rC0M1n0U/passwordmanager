export default function handler(req, res) {
  // Construire une URL OAuth2 Google (PKCE non implémenté dans cette démo)
  const clientId = process.env.GOOGLE_CLIENT_ID
  const redirectUri = process.env.GOOGLE_REDIRECT_URI || `${process.env.NEXT_PUBLIC_BASE_URL || ''}/api/auth/callback`

  if (!clientId) {
    return res.status(500).json({ error: 'GOOGLE_CLIENT_ID non configuré' })
  }

  const params = new URLSearchParams({
    client_id: clientId,
    redirect_uri: redirectUri,
    response_type: 'code',
    scope: 'openid profile email https://www.googleapis.com/auth/userinfo.profile',
    access_type: 'offline',
    prompt: 'consent'
  })

  const url = `https://accounts.google.com/o/oauth2/v2/auth?${params.toString()}`
  res.status(200).json({ url })
}
