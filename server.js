import express from 'express';
import cors from 'cors';
import { analyzePayload, analyzeUrl } from './analyzer.js';

const app = express();
const PORT = process.env.PORT || 5000;

// Enable CORS for frontend development
app.use(cors());
app.use(express.json({ limit: '10mb' }));

/**
 * Health check endpoint
 */
app.get('/api/health', (req, res) => {
  res.json({
    status: 'ok',
    service: 'QRShield Security API',
    uptime: process.uptime(),
    timestamp: new Date().toISOString()
  });
});

/**
 * Safely check if a URL redirects (URL unshortener)
 */
async function resolveRedirect(targetUrl) {
  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 3500);

    const response = await fetch(targetUrl, {
      method: 'HEAD',
      redirect: 'manual',
      headers: {
        'User-Agent': 'QRShield-Security-Bot/1.0'
      },
      signal: controller.signal
    });
    clearTimeout(timeout);

    const location = response.headers.get('location');
    if (location) {
      return new URL(location, targetUrl).href;
    }
  } catch {
    // If HEAD request fails, we safely ignore and evaluate the target URL directly
  }
  return null;
}

/**
 * Analyze QR content / URL for security threats
 */
app.post('/api/analyze', async (req, res) => {
  try {
    const { content } = req.body;

    if (!content || typeof content !== 'string' || !content.trim()) {
      return res.status(400).json({
        success: false,
        error: 'No QR content provided for analysis.'
      });
    }

    const trimmedContent = content.trim();
    const baseAnalysis = analyzePayload(trimmedContent);

    // If it's a shortened URL, attempt to discover the expanded destination
    if (baseAnalysis.contentType === 'URL' && baseAnalysis.parsedUrl) {
      const redirectDestination = await resolveRedirect(baseAnalysis.parsedUrl.href);
      if (redirectDestination && redirectDestination !== baseAnalysis.parsedUrl.href) {
        const redirectedAnalysis = analyzeUrl(redirectDestination);
        baseAnalysis.unshortenedUrl = redirectDestination;
        baseAnalysis.finalDestinationAnalysis = redirectedAnalysis;

        // If the unshortened link is dangerous, elevate the main verdict
        if (redirectedAnalysis.riskScore > baseAnalysis.riskScore) {
          baseAnalysis.riskScore = redirectedAnalysis.riskScore;
          baseAnalysis.verdict = redirectedAnalysis.verdict;
          baseAnalysis.findings.push({
            severity: redirectedAnalysis.verdict === 'DANGEROUS' ? 'danger' : 'warning',
            title: `Hidden Destination Unmasked: ${redirectedAnalysis.parsedUrl.hostname}`,
            description: `This link redirects to ${redirectDestination}. Risk score updated to reflect destination.`
          });
        }
      }
    }

    res.json({
      success: true,
      data: baseAnalysis
    });
  } catch (error) {
    console.error('Error during analysis:', error);
    res.status(500).json({
      success: false,
      error: 'An internal error occurred while analyzing the target destination.'
    });
  }
});

app.listen(PORT, () => {
  console.log(`🛡️ QRShield Backend Server running on http://localhost:${PORT}`);
});

