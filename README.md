# PhishGuard

A phishing email analyzer that combines AI-powered detection with rule-based pattern matching to instantly assess whether an email is legitimate or a phishing attempt.
Live Demo: https://claude.ai/public/artifacts/bb4a51f6-e7ff-436a-ad56-37c06a5550bf

What It Does
Users paste a suspicious email (or fill in the fields manually) and PhishGuard returns:

A risk score from 0–100
A verdict: Safe, Suspicious, or Phishing Detected
A breakdown of every red flag found, labeled by severity (High / Medium / Low)
A plain-English AI summary of the findings


How It Works
PhishGuard runs two detection engines simultaneously and combines the results:
Rule-Based Engine (40% weight)
Scans for known phishing patterns including:

Urgency and pressure language
Credential harvesting attempts
Threatening language
Sender domain mismatches
Shortened or insecure URLs
Brand name spoofing (character substitution)
Generic greetings

AI Engine via Claude API (60% weight)
Sends the email to Claude for contextual analysis catches nuanced threats that simple pattern matching would miss and returns structured findings with severity ratings.

Security Features

Input sanitization : strips all HTML tags and JavaScript before processing
Prompt injection protection : user-supplied email content is wrapped in hard delimiters and the AI is explicitly instructed to treat all content as untrusted data, not instructions
Character limits : enforced on all inputs to prevent abuse


Tech Stack

React
Claude API (claude-sonnet-4-20250514)
Vanilla CSS with CSS custom propertie


<img width="402" height="412" alt="image" src="https://github.com/user-attachments/assets/3e14ff26-3a86-4917-9ba2-770aab7a55fb" />


_AI-powered phishing email analyzer built with React and Claude API, combines rule-based pattern detection with live AI analysis to score and break down suspicious email_
