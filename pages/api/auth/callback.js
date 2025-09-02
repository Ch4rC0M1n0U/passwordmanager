export default async function handler(req, res) {
  const { code } = req.query
  if (!code) {
    return res.status(400).send('Code manquant')
  }

  const clientId = process.env.GOOGLE_CLIENT_ID
  const clientSecret = process.env.GOOGLE_CLIENT_SECRET
  const redirectUri = process.env.GOOGLE_REDIRECT_URI || `${process.env.NEXT_PUBLIC_BASE_URL || ''}/api/auth/callback`

  if (!clientId || !clientSecret) {
    return res.status(500).send('Variables d\'environnement Google manquantes')
  }

  try {
    const tokenRes = await fetch('https://oauth2.googleapis.com/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        code,
        client_id: clientId,
        client_secret: clientSecret,
        redirect_uri: redirectUri,
        grant_type: 'authorization_code'
      })
    })

    const tokenJson = await tokenRes.json()
    if (tokenJson.error) {
      console.error('Token error', tokenJson)
      return res.status(500).send('Erreur lors de la récupération du token')
    }

    const accessToken = tokenJson.access_token

    // Récupérer le profil utilisateur via l'endpoint userinfo
    const profileRes = await fetch('https://www.googleapis.com/oauth2/v3/userinfo', {
      headers: { Authorization: `Bearer ${accessToken}` }
    })
    const profile = await profileRes.json()

    // Retourner une page HTML qui poste le profil à la fenêtre parent (popup)
    const html = `
      <html>
        <head><meta charset="utf-8" /></head>
        <body>
          <script>
            try {
              const profile = ${JSON.stringify(profile)};
              window.opener.postMessage({ type: 'oauth_profile', profile }, window.location.origin);
            } catch (e) {
              console.error(e)
            }
            // close the popup
            window.close();
          </script>
          <p>Connexion réussie, vous pouvez fermer cette fenêtre.</p>
        </body>
      </html>
    `

    res.setHeader('Content-Type', 'text/html')
    res.status(200).send(html)
  } catch (err) {
    console.error(err)
    res.status(500).send('Erreur interne')
  }
}
