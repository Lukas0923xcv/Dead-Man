#!/usr/bin/env python3
"""
SecureVault: Minimalist 256-Bit Dual-Key Split Encryption & Custody Handover Server.
- Hosted in Switzerland (Swiss Data Privacy & Zero Telemetry).
- Bilingual (German default/base with English toggle).
- Clean, Uncluttered Landing Page with "More Information" Modal / Drawer.
- Automated Inactivity Handover (30-Day Dead Man's Switch) + Manual Handover.
- Zero-Knowledge Storage: Files, filenames, and notes are encrypted with AES-256-GCM split keys.
"""

import argparse
import datetime
import json
import os
import secrets
import signal
import ssl
import sys
import threading
import time
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Dict, List, Optional, Tuple
from urllib.parse import parse_qs, urlparse

from code_generator import (
    CHARSETS,
    DEFAULT_CHARSET,
    DEFAULT_LENGTH,
    MAX_LENGTH,
    generate_code,
)
from crypto_engine import (
    DEFAULT_KEY_BITS,
    decrypt_split,
    decrypt_text,
    encrypt_split,
    encrypt_text,
)
import email_service
import monitor_server
import storage

SERVER_START_TIME = time.time()
SERVER_VERSION = "5.9.0"
DEFAULT_INACTIVITY_DAYS = int(os.getenv("INACTIVITY_DAYS", "30"))

HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="de" data-theme="light">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>SecureVault — Zero-Knowledge Cryptographic Custody</title>
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&family=JetBrains+Mono:wght@400;500;600&display=swap" rel="stylesheet">
  <style>
    :root, [data-theme="light"] {
      --bg: #ebedf0;
      --card-bg: #ffffff;
      --card-subtle: #f1f4f8;
      --input-bg: #ffffff;
      --border: #cbd5e1;
      --border-subtle: #94a3b8;
      --border-focus: #0f172a;
      --text: #334155;
      --text-bright: #0f172a;
      --text-muted: #64748b;
      --btn-primary: #0f172a;
      --btn-primary-text: #ffffff;
      --btn-primary-hover: #1e293b;
      --btn-secondary: #ffffff;
      --btn-secondary-text: #0f172a;
      --btn-secondary-hover: #f1f4f8;
      --accent: #2563eb;
      --success: #16a34a;
      --success-bg: #f0fdf4;
      --success-border: #86efac;
      --warning-bg: #fffbeb;
      --warning-border: #fde68a;
      --warning-text: #92400e;
      --error-bg: #fef2f2;
      --error-border: #fecaca;
      --error-text: #991b1b;
      --shadow: 0 1px 3px 0 rgba(0, 0, 0, 0.08), 0 1px 2px 0 rgba(0, 0, 0, 0.04);
      --card-shadow: 0 10px 28px -4px rgba(0, 0, 0, 0.07), 0 2px 6px -2px rgba(0, 0, 0, 0.04), 0 0 0 1px #cbd5e1;
    }

    [data-theme="dark"] {
      --bg: #09090b;
      --card-bg: #18181c;
      --card-subtle: #242429;
      --input-bg: #101014;
      --border: #38383f;
      --border-subtle: #52525c;
      --border-focus: #818cf8;
      --text: #a1a1aa;
      --text-bright: #ffffff;
      --text-muted: #71717a;
      --btn-primary: #f4f4f5;
      --btn-primary-text: #09090b;
      --btn-primary-hover: #e4e4e7;
      --btn-secondary: #18181c;
      --btn-secondary-text: #f4f4f5;
      --btn-secondary-hover: #242429;
      --accent: #6366f1;
      --success: #10b981;
      --success-bg: rgba(16, 185, 129, 0.1);
      --success-border: rgba(16, 185, 129, 0.3);
      --warning-bg: rgba(245, 158, 11, 0.1);
      --warning-border: rgba(245, 158, 11, 0.3);
      --warning-text: #fde68a;
      --error-bg: rgba(239, 68, 68, 0.1);
      --error-border: rgba(239, 68, 68, 0.3);
      --error-text: #fca5a5;
      --shadow: 0 4px 20px rgba(0, 0, 0, 0.5);
      --card-shadow: 0 16px 40px -4px rgba(0, 0, 0, 0.7), 0 0 0 1px #38383f;
    }

    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      background-color: var(--bg);
      color: var(--text);
      font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
      min-height: 100vh;
      display: flex;
      flex-direction: column;
      align-items: center;
      padding: 28px 16px 20px;
      -webkit-font-smoothing: antialiased;
      transition: background-color 0.2s ease, color 0.2s ease;
    }
    .container {
      width: 100%;
      max-width: 760px;
    }

    /* Top Navigation */
    .header {
      display: flex;
      align-items: center;
      justify-content: space-between;
      margin-bottom: 24px;
      padding-bottom: 14px;
      border-bottom: 1px solid var(--border);
    }
    .brand {
      display: flex;
      align-items: center;
      gap: 10px;
      cursor: pointer;
      text-decoration: none;
    }
    .brand-icon {
      width: 32px;
      height: 32px;
      background: var(--btn-primary);
      color: var(--btn-primary-text);
      border-radius: 8px;
      display: flex;
      align-items: center;
      justify-content: center;
    }
    .brand-title {
      font-size: 16px;
      font-weight: 700;
      color: var(--text-bright);
      letter-spacing: -0.02em;
    }
    .header-actions {
      display: flex;
      align-items: center;
      gap: 8px;
    }
    .nav-link-btn {
      background: transparent;
      border: 1px solid var(--border);
      color: var(--text-bright);
      font-family: inherit;
      font-size: 13px;
      font-weight: 600;
      padding: 6px 12px;
      border-radius: 6px;
      cursor: pointer;
      transition: all 0.15s ease;
    }
    .nav-link-btn:hover {
      background: var(--card-subtle);
    }

    /* Language Switcher */
    .lang-switch {
      display: inline-flex;
      align-items: center;
      background: var(--card-subtle);
      border: 1px solid var(--border);
      border-radius: 6px;
      padding: 2px 4px;
      gap: 2px;
    }
    .lang-btn {
      background: transparent;
      border: none;
      color: var(--text-muted);
      font-family: inherit;
      font-size: 11.5px;
      font-weight: 700;
      padding: 3px 6px;
      border-radius: 4px;
      cursor: pointer;
      transition: all 0.15s ease;
    }
    .lang-btn:hover {
      color: var(--text-bright);
    }
    .lang-btn.active {
      background: var(--card-bg);
      color: var(--text-bright);
      box-shadow: var(--shadow);
    }
    .lang-divider {
      color: var(--border-subtle);
      font-size: 11px;
    }

    .theme-toggle {
      background: transparent;
      border: 1px solid var(--border);
      color: var(--text-muted);
      width: 32px;
      height: 32px;
      border-radius: 6px;
      display: flex;
      align-items: center;
      justify-content: center;
      cursor: pointer;
      transition: all 0.15s ease;
    }
    .theme-toggle:hover {
      background: var(--card-subtle);
      color: var(--text-bright);
    }

    /* =========================================================================
       CLEAN, SPACIOUS HERO (NOT PACKED)
       ========================================================================= */
    #view-home {
      display: block;
      animation: fadeIn 0.2s ease-out;
    }
    .hero-clean {
      text-align: center;
      padding: 24px 0 32px;
    }
    .hero-title-clean {
      font-size: 30px;
      font-weight: 800;
      color: var(--text-bright);
      letter-spacing: -0.03em;
      line-height: 1.25;
      margin-bottom: 12px;
    }
    .hero-desc-clean {
      font-size: 15px;
      color: var(--text);
      line-height: 1.6;
      max-width: 600px;
      margin: 0 auto 24px;
    }
    .hero-actions-clean {
      display: flex;
      align-items: center;
      justify-content: center;
      gap: 10px;
      flex-wrap: wrap;
      margin-bottom: 32px;
    }
    .btn-hero-primary {
      background: var(--btn-primary);
      color: var(--btn-primary-text);
      border: none;
      border-radius: 8px;
      font-family: inherit;
      font-size: 14.5px;
      font-weight: 600;
      padding: 11px 22px;
      cursor: pointer;
      display: inline-flex;
      align-items: center;
      gap: 8px;
      box-shadow: var(--shadow);
      transition: all 0.15s ease;
    }
    .btn-hero-primary:hover {
      background: var(--btn-primary-hover);
      transform: translateY(-1px);
    }
    .btn-hero-secondary {
      background: var(--btn-secondary);
      color: var(--btn-secondary-text);
      border: 1px solid var(--border);
      border-radius: 8px;
      font-family: inherit;
      font-size: 14.5px;
      font-weight: 600;
      padding: 11px 18px;
      cursor: pointer;
      display: inline-flex;
      align-items: center;
      gap: 6px;
      box-shadow: var(--shadow);
      transition: all 0.15s ease;
    }
    .btn-hero-secondary:hover {
      background: var(--card-subtle);
    }
    .btn-hero-info {
      background: transparent;
      color: var(--text-muted);
      border: 1px solid var(--border);
      border-radius: 8px;
      font-family: inherit;
      font-size: 14px;
      font-weight: 600;
      padding: 11px 16px;
      cursor: pointer;
      display: inline-flex;
      align-items: center;
      gap: 6px;
      transition: all 0.15s ease;
    }
    .btn-hero-info:hover {
      color: var(--text-bright);
      border-color: var(--border-focus);
      background: var(--card-subtle);
    }

    /* Minimalist 3-Pill Highlights */
    .highlights-bar {
      display: grid;
      grid-template-columns: repeat(3, 1fr);
      gap: 12px;
      margin-bottom: 24px;
    }
    @media (max-width: 600px) {
      .highlights-bar { grid-template-columns: 1fr; }
    }
    .highlight-card {
      background: var(--card-bg);
      border: 1px solid var(--border);
      border-radius: 10px;
      padding: 16px;
      text-align: center;
      box-shadow: var(--card-shadow);
      display: flex;
      flex-direction: column;
      align-items: center;
      gap: 6px;
    }
    .highlight-icon {
      font-size: 20px;
      margin-bottom: 2px;
    }
    .highlight-title {
      font-size: 13.5px;
      font-weight: 700;
      color: var(--text-bright);
    }
    .highlight-desc {
      font-size: 12px;
      color: var(--text-muted);
      line-height: 1.4;
    }

    /* =========================================================================
       "MORE INFORMATION" MODAL DIALOG
       ========================================================================= */
    .modal-overlay {
      position: fixed;
      top: 0;
      left: 0;
      right: 0;
      bottom: 0;
      background: rgba(15, 23, 42, 0.65);
      backdrop-filter: blur(8px);
      -webkit-backdrop-filter: blur(8px);
      display: none;
      align-items: center;
      justify-content: center;
      z-index: 1000;
      padding: 16px;
      animation: fadeIn 0.15s ease-out;
    }
    .modal-container {
      background: var(--card-bg);
      border: 1px solid var(--border);
      border-radius: 16px;
      box-shadow: 0 24px 48px -12px rgba(0, 0, 0, 0.35), 0 0 0 1px var(--border);
      width: 100%;
      max-width: 780px;
      max-height: 90vh;
      display: flex;
      flex-direction: column;
      overflow: hidden;
    }
    .modal-header {
      display: flex;
      align-items: center;
      justify-content: space-between;
      padding: 18px 24px;
      border-bottom: 1px solid var(--border);
      background: var(--card-subtle);
    }
    .modal-title {
      font-size: 15.5px;
      font-weight: 700;
      color: var(--text-bright);
      display: flex;
      align-items: center;
      gap: 10px;
      letter-spacing: -0.01em;
    }
    .modal-close-btn {
      width: 28px;
      height: 28px;
      background: transparent;
      border: none;
      color: var(--text-muted);
      cursor: pointer;
      font-size: 16px;
      border-radius: 6px;
      display: flex;
      align-items: center;
      justify-content: center;
      transition: all 0.15s ease;
    }
    .modal-close-btn:hover {
      background: var(--border);
      color: var(--text-bright);
    }
    .modal-body {
      padding: 24px;
      overflow-y: auto;
    }

    /* Architecture Pipeline Flow Inside Modal */
    .flow-card {
      background: var(--card-subtle);
      border: 1px solid var(--border);
      border-radius: 10px;
      padding: 14px 16px;
      margin-bottom: 16px;
    }
    .flow-title {
      font-size: 11px;
      font-weight: 700;
      text-transform: uppercase;
      letter-spacing: 0.05em;
      color: var(--text-muted);
      margin-bottom: 10px;
    }
    .flow-steps {
      display: grid;
      grid-template-columns: repeat(4, 1fr);
      gap: 10px;
    }
    @media (max-width: 620px) {
      .flow-steps { grid-template-columns: 1fr 1fr; }
    }
    .flow-step-item {
      background: var(--card-bg);
      border: 1px solid var(--border);
      border-radius: 7px;
      padding: 10px 12px;
    }
    .flow-step-num {
      font-size: 10.5px;
      font-weight: 700;
      color: var(--accent);
      margin-bottom: 3px;
    }
    .flow-step-name {
      font-size: 12.5px;
      font-weight: 700;
      color: var(--text-bright);
      margin-bottom: 2px;
    }
    .flow-step-sub {
      font-size: 11px;
      color: var(--text-muted);
      line-height: 1.35;
    }

    /* 6-Card Feature Grid Inside Modal */
    .feature-grid-modal {
      display: grid;
      grid-template-columns: repeat(2, 1fr);
      gap: 10px;
      margin-bottom: 16px;
    }
    @media (max-width: 560px) {
      .feature-grid-modal { grid-template-columns: 1fr; }
    }
    .feature-card-modal {
      background: var(--card-subtle);
      border: 1px solid var(--border);
      border-radius: 9px;
      padding: 14px;
      display: flex;
      flex-direction: column;
      gap: 6px;
    }
    .feature-card-modal h3 {
      font-size: 13px;
      font-weight: 700;
      color: var(--text-bright);
    }
    .feature-card-modal p {
      font-size: 12px;
      color: var(--text);
      line-height: 1.45;
    }

    /* Specs Strip Inside Modal */
    .specs-strip-modal {
      display: flex;
      align-items: center;
      justify-content: space-between;
      background: var(--card-subtle);
      border: 1px solid var(--border);
      border-radius: 8px;
      padding: 10px 14px;
      font-size: 11.5px;
      font-weight: 500;
      color: var(--text-muted);
      flex-wrap: wrap;
      gap: 8px;
    }
    .spec-item strong {
      color: var(--text-bright);
    }

    /* =========================================================================
       VAULT APP (SUBPAGE VIEW)
       ========================================================================= */
    #view-app {
      display: none;
      animation: fadeIn 0.2s ease-out;
      max-width: 640px;
      margin: 0 auto;
    }
    @keyframes fadeIn {
      from { opacity: 0; transform: translateY(6px); }
      to { opacity: 1; transform: translateY(0); }
    }

    /* Segmented Navigation */
    .nav-tabs {
      display: flex;
      background: var(--card-subtle);
      border: 1px solid var(--border);
      border-radius: 9px;
      padding: 3px;
      margin-bottom: 16px;
      gap: 3px;
    }
    .tab-btn {
      flex: 1;
      background: transparent;
      border: none;
      color: var(--text-muted);
      font-family: inherit;
      font-size: 12.5px;
      font-weight: 600;
      padding: 7px 10px;
      border-radius: 6px;
      cursor: pointer;
      transition: all 0.15s ease;
      display: flex;
      align-items: center;
      justify-content: center;
      gap: 5px;
    }
    .tab-btn:hover {
      color: var(--text-bright);
    }
    .tab-btn.active {
      background: var(--card-bg);
      color: var(--text-bright);
      box-shadow: var(--shadow);
    }

    /* Card Container */
    .card {
      background: var(--card-bg);
      border: 1px solid var(--border);
      border-radius: 12px;
      box-shadow: var(--card-shadow);
      padding: 22px;
      margin-bottom: 16px;
    }
    .card-header {
      margin-bottom: 16px;
    }
    .card-title {
      font-size: 15px;
      font-weight: 600;
      color: var(--text-bright);
    }
    .card-subtitle {
      font-size: 12.5px;
      color: var(--text-muted);
      margin-top: 2px;
    }

    /* Form Fields */
    .form-group {
      margin-bottom: 16px;
    }
    label {
      display: block;
      font-size: 13px;
      font-weight: 600;
      color: var(--text-bright);
      margin-bottom: 6px;
      letter-spacing: -0.01em;
    }
    .hint {
      font-size: 11.5px;
      font-weight: 400;
      color: var(--text-muted);
      margin-left: 4px;
    }
    textarea,
    input[type="text"],
    input[type="email"],
    input[type="password"],
    input {
      width: 100%;
      height: 42px;
      background: var(--input-bg);
      border: 1.5px solid var(--border);
      border-radius: 8px;
      color: var(--text-bright);
      font-family: inherit;
      font-size: 13.5px;
      padding: 0 12px;
      box-sizing: border-box;
      transition: all 0.15s ease;
    }
    textarea {
      height: auto;
      min-height: 92px;
      padding: 10px 12px;
      resize: vertical;
      line-height: 1.45;
    }
    textarea:focus,
    input:focus {
      outline: none;
      border-color: var(--accent);
      box-shadow: 0 0 0 3px rgba(99, 102, 241, 0.16);
      background: var(--card-bg);
    }
    textarea::placeholder,
    input::placeholder {
      color: var(--text-muted);
      opacity: 0.8;
    }

    /* File Attachment Dropzone / Picker */
    .file-dropzone {
      border: 1.5px dashed var(--border-subtle);
      background: var(--card-subtle);
      border-radius: 7px;
      padding: 12px;
      text-align: center;
      cursor: pointer;
      transition: all 0.15s ease;
      display: flex;
      flex-direction: column;
      align-items: center;
      justify-content: center;
      gap: 4px;
    }
    .file-dropzone:hover {
      border-color: var(--border-focus);
      background: var(--input-bg);
    }
    .file-dropzone svg {
      color: var(--text-muted);
    }
    .file-dropzone-text {
      font-size: 12.5px;
      font-weight: 500;
      color: var(--text-bright);
    }
    .file-dropzone-hint {
      font-size: 11px;
      color: var(--text-muted);
    }
    .attached-file-pill {
      display: none;
      align-items: center;
      justify-content: space-between;
      background: var(--card-subtle);
      border: 1px solid var(--border);
      border-radius: 7px;
      padding: 8px 12px;
      margin-top: 6px;
    }
    .attached-file-info {
      display: flex;
      align-items: center;
      gap: 8px;
      overflow: hidden;
    }
    .attached-file-name {
      font-size: 12.5px;
      font-weight: 600;
      color: var(--text-bright);
      white-space: nowrap;
      overflow: hidden;
      text-overflow: ellipsis;
      max-width: 280px;
    }
    .attached-file-size {
      font-size: 11px;
      color: var(--text-muted);
    }
    .remove-file-btn {
      background: transparent;
      border: none;
      color: var(--text-muted);
      cursor: pointer;
      padding: 3px;
      border-radius: 4px;
      display: flex;
      align-items: center;
      justify-content: center;
    }
    .remove-file-btn:hover {
      color: var(--error-text);
      background: var(--error-bg);
    }

    /* Clean Buttons */
    .btn-main {
      background: var(--btn-primary);
      color: var(--btn-primary-text);
      border: none;
      border-radius: 7px;
      font-family: inherit;
      font-size: 13.5px;
      font-weight: 600;
      padding: 10px 16px;
      cursor: pointer;
      transition: background 0.15s ease;
      width: 100%;
      display: flex;
      align-items: center;
      justify-content: center;
      gap: 7px;
    }
    .btn-main:hover {
      background: var(--btn-primary-hover);
    }
    .btn-copy {
      background: var(--btn-secondary);
      color: var(--btn-secondary-text);
      border: 1px solid var(--border);
      font-family: inherit;
      font-size: 11.5px;
      font-weight: 500;
      padding: 3px 8px;
      border-radius: 5px;
      cursor: pointer;
      transition: background 0.15s ease;
      display: inline-flex;
      align-items: center;
      gap: 4px;
    }
    .btn-copy:hover {
      background: var(--card-subtle);
    }
    .btn-download {
      background: var(--btn-primary);
      color: var(--btn-primary-text);
      border: none;
      font-family: inherit;
      font-size: 12.5px;
      font-weight: 600;
      padding: 7px 12px;
      border-radius: 6px;
      cursor: pointer;
      display: inline-flex;
      align-items: center;
      gap: 5px;
      transition: opacity 0.15s ease;
    }
    .btn-download:hover {
      opacity: 0.9;
    }

    /* Result Displays */
    .result-box {
      margin-top: 16px;
      padding-top: 16px;
      border-top: 1px solid var(--border);
      display: none;
    }
    .item-card {
      background: var(--card-subtle);
      border: 1px solid var(--border);
      border-radius: 7px;
      padding: 10px 12px;
      margin-bottom: 10px;
    }
    .item-header {
      display: flex;
      justify-content: space-between;
      align-items: center;
      margin-bottom: 4px;
    }
    .item-label {
      font-size: 10.5px;
      font-weight: 600;
      text-transform: uppercase;
      letter-spacing: 0.04em;
      color: var(--text-muted);
    }
    .item-code {
      font-family: 'JetBrains Mono', monospace;
      font-size: 12.5px;
      color: var(--text-bright);
      word-break: break-all;
      line-height: 1.45;
    }
    .item-code.large {
      font-size: 17px;
      font-weight: 700;
      letter-spacing: 0.08em;
    }

    /* Decrypted File Card */
    .decrypted-file-card {
      display: flex;
      align-items: center;
      justify-content: space-between;
      background: var(--card-subtle);
      border: 1px solid var(--border);
      border-radius: 7px;
      padding: 12px;
      margin-bottom: 10px;
    }

    /* Alerts */
    .alert {
      padding: 10px 12px;
      border-radius: 7px;
      font-size: 12.5px;
      line-height: 1.45;
      margin-bottom: 14px;
      display: flex;
      align-items: flex-start;
      gap: 7px;
    }
    .alert-success {
      background: var(--success-bg);
      border: 1px solid var(--success-border);
      color: var(--text-bright);
    }
    .alert-warning {
      background: var(--warning-bg);
      border: 1px solid var(--warning-border);
      color: var(--warning-text);
    }
    .alert-error {
      background: var(--error-bg);
      border: 1px solid var(--error-border);
      color: var(--error-text);
      display: none;
    }

    /* Auth Navigation Controls */
    .nav-auth-section {
      display: flex;
      align-items: center;
      gap: 6px;
      margin-left: 4px;
    }
    .btn-auth-nav {
      background: var(--card-subtle);
      border: 1px solid var(--border);
      color: var(--text);
      font-family: inherit;
      font-size: 11.5px;
      font-weight: 600;
      padding: 5px 9px;
      border-radius: 6px;
      cursor: pointer;
      transition: all 0.15s ease;
    }
    .btn-auth-nav:hover {
      background: var(--card-hover);
      color: var(--text-bright);
      border-color: var(--text-muted);
    }
    .btn-auth-nav.primary {
      background: var(--accent);
      color: #ffffff;
      border-color: transparent;
    }
    .btn-auth-nav.primary:hover {
      opacity: 0.9;
    }
    .user-badge {
      display: inline-flex;
      align-items: center;
      gap: 6px;
      background: var(--card-subtle);
      border: 1px solid var(--border);
      padding: 4px 9px;
      border-radius: 6px;
      font-size: 11.5px;
      font-weight: 600;
      color: var(--text-bright);
    }
    .user-dot {
      width: 7px;
      height: 7px;
      border-radius: 50%;
      background: var(--success);
    }

    /* Auth Modal & Tabs */
    .auth-tabs {
      display: flex;
      background: var(--card-subtle);
      border: 1px solid var(--border);
      border-radius: 10px;
      padding: 4px;
      margin-bottom: 20px;
      gap: 4px;
    }
    .auth-tab-btn {
      flex: 1;
      background: transparent;
      border: none;
      color: var(--text-muted);
      font-family: inherit;
      font-size: 13px;
      font-weight: 600;
      padding: 8px 12px;
      border-radius: 7px;
      cursor: pointer;
      transition: all 0.15s ease;
    }
    .auth-tab-btn:hover {
      color: var(--text-bright);
    }
    .auth-tab-btn.active {
      background: var(--card-bg);
      color: var(--text-bright);
      box-shadow: 0 1px 3px rgba(0, 0, 0, 0.1);
    }
    .auth-switch-link {
      display: block;
      text-align: center;
      font-size: 13px;
      font-weight: 500;
      color: var(--accent);
      margin-top: 16px;
      cursor: pointer;
      text-decoration: none;
      transition: color 0.15s ease;
    }
    .auth-switch-link:hover {
      text-decoration: underline;
    }

    /* Auth Guard Card */
    .guard-card {
      text-align: center;
      padding: 32px 20px;
    }
    .guard-icon {
      font-size: 32px;
      margin-bottom: 12px;
    }
    .guard-title {
      font-size: 16px;
      font-weight: 700;
      color: var(--text-bright);
      margin-bottom: 6px;
    }
    .guard-desc {
      font-size: 12.5px;
      color: var(--text-muted);
      max-width: 400px;
      margin: 0 auto 18px;
      line-height: 1.45;
    }

    /* User Vaults List & Cards */
    .vaults-header-bar {
      display: flex;
      justify-content: space-between;
      align-items: center;
      margin-bottom: 16px;
    }
    .vault-count-badge {
      font-size: 11px;
      font-weight: 700;
      background: var(--accent);
      color: #fff;
      padding: 2px 6px;
      border-radius: 10px;
      margin-left: 4px;
    }
    .vaults-list {
      display: flex;
      flex-direction: column;
      gap: 12px;
    }
    .vault-item-card {
      background: var(--card-subtle);
      border: 1px solid var(--border);
      border-radius: 9px;
      padding: 14px;
      transition: all 0.15s ease;
    }
    .vault-item-card:hover {
      border-color: var(--text-muted);
    }
    .vault-card-top {
      display: flex;
      justify-content: space-between;
      align-items: center;
      margin-bottom: 8px;
    }
    .vault-code-tag {
      font-family: 'JetBrains Mono', monospace;
      font-size: 14px;
      font-weight: 700;
      color: var(--text-bright);
      letter-spacing: 0.04em;
    }
    .status-pill {
      font-size: 10.5px;
      font-weight: 700;
      text-transform: uppercase;
      letter-spacing: 0.04em;
      padding: 3px 8px;
      border-radius: 20px;
    }
    .status-pill.active {
      background: rgba(46, 160, 67, 0.15);
      color: #2ea043;
      border: 1px solid rgba(46, 160, 67, 0.3);
    }
    .status-pill.inherited {
      background: rgba(210, 153, 34, 0.15);
      color: #d29922;
      border: 1px solid rgba(210, 153, 34, 0.3);
    }
    .status-pill.stopped {
      background: rgba(248, 81, 73, 0.15);
      color: #f85149;
      border: 1px solid rgba(248, 81, 73, 0.3);
    }
    .vault-meta-row {
      font-size: 12px;
      color: var(--text-muted);
      margin-bottom: 4px;
      display: flex;
      flex-wrap: wrap;
      gap: 12px;
    }
    .vault-meta-item strong {
      color: var(--text);
    }
    .vault-actions-row {
      display: flex;
      gap: 8px;
      margin-top: 10px;
      padding-top: 10px;
      border-top: 1px solid var(--border);
    }
    .btn-vault-action {
      background: var(--card-bg);
      border: 1px solid var(--border);
      color: var(--text);
      font-family: inherit;
      font-size: 11.5px;
      font-weight: 600;
      padding: 5px 10px;
      border-radius: 5px;
      cursor: pointer;
      transition: all 0.12s ease;
    }
    .btn-vault-action:hover {
      background: var(--card-hover);
      color: var(--text-bright);
      border-color: var(--text-muted);
    }
    .btn-vault-action.primary {
      background: var(--accent);
      color: #ffffff;
      border-color: transparent;
    }
    .btn-vault-action.danger {
      color: var(--danger, #f85149);
    }
    .btn-vault-action.danger:hover {
      background: rgba(248, 81, 73, 0.1);
      border-color: rgba(248, 81, 73, 0.4);
    }

    footer {
      text-align: center;
      font-size: 11.5px;
      color: var(--text-muted);
      margin-top: auto;
      padding-top: 20px;
    }
  </style>
</head>
<body>
  <div class="container">
    
    <!-- Navigation Bar -->
    <header class="header">
      <div class="brand" onclick="navigateTo('home')">
        <div class="brand-icon">
          <svg width="17" height="17" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round">
            <rect x="3" y="11" width="18" height="11" rx="2" ry="2"/>
            <path d="M7 11V7a5 5 0 0 1 10 0v4"/>
          </svg>
        </div>
        <div class="brand-title">SecureVault</div>
      </div>
      <div class="header-actions">
        <button class="nav-link-btn" id="nav-btn-home" onclick="navigateTo('home')" data-i18n="nav_overview">Übersicht</button>
        <button class="nav-link-btn" onclick="openInfoModal()" data-i18n="nav_info">Info</button>
        
        <!-- Language Switcher (DE base) -->
        <div class="lang-switch">
          <button class="lang-btn active" id="lang-btn-de" onclick="setLanguage('de')">DE</button>
          <span class="lang-divider">/</span>
          <button class="lang-btn" id="lang-btn-en" onclick="setLanguage('en')">EN</button>
        </div>

        <button class="theme-toggle" id="theme-btn" onclick="toggleTheme()" title="Toggle Theme">
          <svg id="theme-icon" width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
            <path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z"></path>
          </svg>
        </button>

        <!-- Auth Controls (Login / Register / User Badge) -->
        <div class="nav-auth-section" id="nav-auth-logged-out">
          <button class="btn-auth-nav" onclick="openAuthModal('login')" data-i18n="nav_login">Anmelden</button>
          <button class="btn-auth-nav primary" onclick="openAuthModal('register')" data-i18n="nav_register">Registrieren</button>
        </div>
        <div class="nav-auth-section" id="nav-auth-logged-in" style="display: none;">
          <div class="user-badge" id="nav-user-badge">
            <span class="user-dot"></span>
            <span id="nav-username">User</span>
          </div>
          <button class="btn-auth-nav" onclick="handleLogout()" data-i18n="nav_logout">Abmelden</button>
        </div>
      </div>
    </header>

    <!-- =====================================================================
         CLEAN, SPACIOUS LANDING PAGE (NOT PACKED)
         ===================================================================== -->
    <div id="view-home">
      <div class="hero-clean">
        <h1 class="hero-title-clean" data-i18n="hero_title">Zero-Knowledge Digitaler Tresor & Kryptographische Verwahrung</h1>
        <p class="hero-desc-clean" data-i18n="hero_desc">
          Vertrauliche Dateien, Zugangsdaten, Dokumente und digitale Nachlässe sicher speichern. Ende-zu-Ende verschlüsselt mit 256-Bit Split-Keys in der Schweiz unter strengsten Datenschutzrichtlinien.
        </p>
        <div class="hero-actions-clean">
          <button class="btn-hero-primary" onclick="navigateTo('app')" data-i18n="btn_open_vault">
            Tresor öffnen →
          </button>
          <button class="btn-hero-info" onclick="openInfoModal()">
            <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
              <circle cx="12" cy="12" r="10"/>
              <line x1="12" y1="16" x2="12" y2="12"/>
              <line x1="12" y1="8" x2="12.01" y2="8"/>
            </svg>
            <span data-i18n="btn_more_info">Mehr Informationen</span>
          </button>
        </div>

        <!-- Minimalist Highlights Bar -->
        <div class="highlights-bar">
          <div class="highlight-card">
            <div class="highlight-icon">🔑</div>
            <div class="highlight-title" data-i18n="hl1_title">Dual-Key Split (256-Bit)</div>
            <div class="highlight-desc" data-i18n="hl1_desc">Weder Schlüssel A noch B allein kann entschlüsseln.</div>
          </div>
          <div class="highlight-card">
            <div class="highlight-icon">🇨🇭</div>
            <div class="highlight-title" data-i18n="hl2_title">Schweizer Zero-Knowledge</div>
            <div class="highlight-desc" data-i18n="hl2_desc">Server speichert 0 KB Klartext. Keine Einsicht möglich.</div>
          </div>
          <div class="highlight-card">
            <div class="highlight-icon">⏳</div>
            <div class="highlight-title" data-i18n="hl3_title">Automatischer Nachlass</div>
            <div class="highlight-desc" data-i18n="hl3_desc">Übergabe nach 30 Tagen Inaktivität oder sofort manuell.</div>
          </div>
        </div>
      </div>
    </div>

    <!-- =====================================================================
         MORE INFORMATION MODAL
         ===================================================================== -->
    <div id="info-modal" class="modal-overlay" onclick="closeInfoModalOnBackdrop(event)">
      <div class="modal-container">
        <div class="modal-header">
          <div class="modal-title">
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round">
              <circle cx="12" cy="12" r="10"/>
              <line x1="12" y1="16" x2="12" y2="12"/>
              <line x1="12" y1="8" x2="12.01" y2="8"/>
            </svg>
            <span data-i18n="modal_title">Funktionsweise & Architektur</span>
          </div>
          <button class="modal-close-btn" onclick="closeInfoModal()" title="Schliessen">✕</button>
        </div>

        <div class="modal-body">
          
          <!-- Architecture Pipeline Card -->
          <div class="flow-card">
            <div class="flow-title" data-i18n="flow_title">Kryptographische Verwahrungs-Pipeline</div>
            <div class="flow-steps">
              <div class="flow-step-item">
                <div class="flow-step-num">STEP 1</div>
                <div class="flow-step-name" data-i18n="step1_title">Geheimnis eingeben</div>
                <div class="flow-step-sub" data-i18n="step1_desc">Text eingeben oder vertrauliche Dateien anhängen.</div>
              </div>
              <div class="flow-step-item">
                <div class="flow-step-num">STEP 2</div>
                <div class="flow-step-name" data-i18n="step2_title">Split-Key Aufteilung</div>
                <div class="flow-step-sub" data-i18n="step2_desc">Erzeugung von 256-Bit Schlüssel A und Schlüssel B.</div>
              </div>
              <div class="flow-step-item">
                <div class="flow-step-num">STEP 3</div>
                <div class="flow-step-name" data-i18n="step3_title">Zero-Knowledge</div>
                <div class="flow-step-sub" data-i18n="step3_desc">Vollständig als Chiffretext vor der Speicherung verschlüsselt.</div>
              </div>
              <div class="flow-step-item">
                <div class="flow-step-num">STEP 4</div>
                <div class="flow-step-name" data-i18n="step4_title">Abrufen / Vererben</div>
                <div class="flow-step-sub" data-i18n="step4_desc">Direkte Geräte-Entschlüsselung oder Nachlass-Übergabe.</div>
              </div>
            </div>
          </div>

          <!-- Feature Grid -->
          <div class="feature-grid-modal">
            <!-- Card 1 -->
            <div class="feature-card-modal">
              <h3 data-i18n="feat1_title">Dual-Key Split (256-Bit)</h3>
              <p data-i18n="feat1_desc">Jeder Datensatz wird in Schlüssel A und Schlüssel B aufgeteilt. Kein Schlüssel allein kann entschlüsseln. Nur beide zusammen stellen Ihre Daten wieder her.</p>
            </div>

            <!-- Card 2 -->
            <div class="feature-card-modal">
              <h3 data-i18n="feat2_title">Gerätegebundener Normalmodus</h3>
              <p data-i18n="feat2_desc">Auf Ihrem Hauptgerät wird Schlüssel B automatisch angewendet. Sie benötigen zur Entschlüsselung lediglich Ihren 16-stelligen Code und Schlüssel A.</p>
            </div>

            <!-- Card 3 -->
            <div class="feature-card-modal">
              <h3 data-i18n="feat3_title">30-Tage Inaktivitäts-Nachlass & Manuelle Übergabe</h3>
              <p data-i18n="feat3_desc">Besuchen Sie die Seite 30 Tage lang nicht (oder lösen Sie die Übergabe manuell aus), wird Schlüssel B per E-Mail an Ihren Erben gesendet und unwiderruflich vom Server gelöscht.</p>
            </div>

            <!-- Card 4 -->
            <div class="feature-card-modal">
              <h3 data-i18n="feat4_title">Verschlüsselte Dateianhänge</h3>
              <p data-i18n="feat4_desc">Vertrauliche PDFs, Dokumente, Ausweiskopien oder Bilder anhängen – mit 1-Klick-Entschlüsselung direkt im Browser.</p>
            </div>

            <!-- Card 5 -->
            <div class="feature-card-modal">
              <h3 data-i18n="feat5_title">Zero-Knowledge Speicher</h3>
              <p data-i18n="feat5_desc">Dateien, Texte und Dateinamen werden vor der Speicherung verschlüsselt. Server-Infrastrukturen haben keinerlei Einsicht in Ihre Daten.</p>
            </div>

            <!-- Card 6 -->
            <div class="feature-card-modal">
              <h3 data-i18n="feat6_title">Schweizer Datenschutz & Standort</h3>
              <p data-i18n="feat6_desc">Betrieben nach strengen Schweizer Datenschutzgesetzen. Höchste Privatsphäre ohne Tracker und ohne Telemetrie.</p>
            </div>
          </div>

          <!-- Specs Strip Inside Modal -->
          <div class="specs-strip-modal">
            <div class="spec-item">🔒 <span data-i18n="spec_enc">Verschlüsselung:</span> <strong>AES-256-GCM</strong></div>
            <div class="spec-item">🔑 <span data-i18n="spec_split">Key-Split:</span> <strong>256-Bit 2-of-2</strong></div>
            <div class="spec-item">⏳ <span data-i18n="spec_inactivity">Inaktivität:</span> <strong data-i18n="spec_inactivity_val">30 Tage</strong></div>
            <div class="spec-item">🏛️ <span data-i18n="spec_juris">Standort:</span> <strong data-i18n="spec_juris_val">Schweiz</strong></div>
          </div>

        </div>
      </div>
    </div>

    <!-- =====================================================================
         AUTHENTICATION MODAL (LOGIN & REGISTER)
         ===================================================================== -->
    <div id="auth-modal" class="modal-overlay" onclick="closeAuthModalOnBackdrop(event)">
      <div class="modal-container" style="max-width: 410px;">
        <div class="modal-header">
          <div class="modal-title">
            <div style="width: 28px; height: 28px; border-radius: 50%; background: rgba(99, 102, 241, 0.12); color: var(--accent); display: flex; align-items: center; justify-content: center; flex-shrink: 0;">
              <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round">
                <path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"/>
                <circle cx="12" cy="7" r="4"/>
              </svg>
            </div>
            <span id="auth-modal-title" data-i18n="auth_modal_title_login">Bei SecureVault anmelden</span>
          </div>
          <button class="modal-close-btn" onclick="closeAuthModal()" title="Schliessen">✕</button>
        </div>

        <div class="modal-body">
          <div class="auth-tabs">
            <button class="auth-tab-btn active" id="auth-tab-login" onclick="switchAuthMode('login')" data-i18n="auth_tab_login">Anmelden</button>
            <button class="auth-tab-btn" id="auth-tab-register" onclick="switchAuthMode('register')" data-i18n="auth_tab_register">Registrieren</button>
          </div>

          <form id="auth-form" onsubmit="handleAuthSubmit(event)">
            <div class="form-group">
              <label for="auth-username" data-i18n="auth_label_username">Benutzername</label>
              <input type="text" id="auth-username" required placeholder="z.B. max_muster" autocomplete="username">
            </div>

            <div class="form-group">
              <label for="auth-password" data-i18n="auth_label_password">Passwort</label>
              <input type="password" id="auth-password" required placeholder="••••••••" autocomplete="current-password">
            </div>

            <div class="form-group" id="auth-confirm-group" style="display: none;">
              <label for="auth-password-confirm" data-i18n="auth_label_password_confirm">Passwort bestätigen</label>
              <input type="password" id="auth-password-confirm" placeholder="••••••••" autocomplete="new-password">
            </div>

            <button type="submit" class="btn-main" id="auth-submit-btn" style="margin-top: 8px;" data-i18n="auth_btn_login">Anmelden</button>

            <div id="auth-error" class="alert alert-error" style="margin-top: 12px;"></div>
            <div id="auth-success" class="alert alert-success" style="margin-top: 12px; display: none;"></div>

            <a class="auth-switch-link" id="auth-toggle-link" onclick="toggleAuthMode()" data-i18n="auth_toggle_to_register">Noch kein Konto? Jetzt registrieren →</a>
          </form>
        </div>
      </div>
    </div>

    <!-- =====================================================================
         DELETE CONFIRMATION MODAL (2-STEP SAFEGUARD)
         ===================================================================== -->
    <div id="delete-modal" class="modal-overlay" onclick="closeDeleteModalOnBackdrop(event)">
      <div class="modal-container" style="max-width: 440px;">
        <div class="modal-header">
          <div class="modal-title" style="color: #f85149;">
            <div style="width: 28px; height: 28px; border-radius: 50%; background: rgba(248, 81, 73, 0.12); color: #f85149; display: flex; align-items: center; justify-content: center; flex-shrink: 0;">
              🗑️
            </div>
            <span data-i18n="delete_modal_title">Tresor & Datei endgültig löschen?</span>
          </div>
          <button class="modal-close-btn" onclick="closeDeleteModal()" title="Schliessen">✕</button>
        </div>

        <div class="modal-body">
          <p style="font-size: 13.5px; line-height: 1.5; color: var(--text-bright); margin-bottom: 14px;">
            <span data-i18n="delete_modal_text_prefix">Möchten Sie den Datensatz mit Code</span> <strong id="delete-modal-code-display" style="font-family: 'JetBrains Mono', monospace; background: var(--card-subtle); padding: 2px 6px; border-radius: 4px; border: 1px solid var(--border);"></strong> <span data-i18n="delete_modal_text_suffix">und alle darin verschlüsselten Dateien wirklich unwiderruflich vom Server löschen?</span>
          </p>

          <div class="alert alert-warning" style="margin-bottom: 18px;">
            ⚠️ <span data-i18n="delete_modal_warning">Diese Aktion kann nicht rückgängig gemacht werden. Der Datensatz und alle Dateien werden sofort und vollständig aus dem Serverspeicher entfernt.</span>
          </div>

          <div id="delete-modal-error" class="alert alert-error" style="display: none; margin-bottom: 14px;"></div>

          <div style="display: flex; gap: 10px; justify-content: flex-end;">
            <button type="button" class="btn-copy" style="padding: 9px 16px; font-size: 13px;" onclick="closeDeleteModal()" data-i18n="delete_modal_cancel">Abbrechen</button>
            <button type="button" class="btn-main" id="delete-modal-confirm-btn" style="width: auto; background: #dc2626; padding: 9px 18px;" onclick="executeDeleteVault()" data-i18n="delete_modal_confirm">🗑️ Unwiderruflich löschen</button>
          </div>
        </div>
      </div>
    </div>

    <!-- =====================================================================
         VAULT SUBPAGE VIEW (ENCRYPT, DECRYPT, INHERIT, MY VAULTS)
         ===================================================================== -->
    <div id="view-app">
      
      <!-- Navigation Tabs -->
      <nav class="nav-tabs">
        <button class="tab-btn active" id="tab-btn-encrypt" onclick="switchTab('encrypt')" data-i18n="tab_encrypt">Verschlüsseln</button>
        <button class="tab-btn" id="tab-btn-decrypt" onclick="switchTab('decrypt')" data-i18n="tab_decrypt">Entschlüsseln</button>
        <button class="tab-btn" id="tab-btn-inherit" onclick="switchTab('inherit')" data-i18n="tab_inherit">Vererbung</button>
        <button class="tab-btn" id="tab-btn-vaults" onclick="switchTab('vaults')" style="display: none;"><span data-i18n="nav_vaults">Meine Tresore</span> <span class="vault-count-badge" id="vault-count" style="display: none;">0</span></button>
      </nav>

      <!-- 1. ENCRYPT PANEL -->
      <div id="tab-encrypt" class="card">
        <!-- Auth Guard if Logged Out -->
        <div id="auth-guard-encrypt" class="guard-card" style="display: none;">
          <div class="guard-icon">🔐</div>
          <div class="guard-title" data-i18n="auth_guard_title">Anmeldung erforderlich</div>
          <div class="guard-desc" data-i18n="auth_guard_desc">Um vertrauliche Daten und Dateien zu verschlüsseln oder Ihre gespeicherten Tresore einzusehen, müssen Sie angemeldet sein.</div>
          <button class="btn-main" style="max-width: 260px; margin: 0 auto;" onclick="openAuthModal('login')" data-i18n="auth_guard_btn">Jetzt anmelden / registrieren</button>
        </div>

        <!-- Encrypt Form Container (visible when logged in) -->
        <div id="enc-form-container">
          <div class="card-header">
            <div class="card-title" data-i18n="enc_title">Daten & Dateien verschlüsseln</div>
            <div class="card-subtitle" data-i18n="enc_subtitle">Verschlüsselt mit Dual-Key-Split. Der Server kann Dateien oder Texte nicht lesen.</div>
          </div>

          <div class="form-group">
            <label for="plaintext"><span data-i18n="enc_label_text">Geheime Notizen / Information</span> <span class="hint" data-i18n="enc_hint_text">(Optional bei Dateianhang)</span></label>
            <textarea id="plaintext" data-i18n-placeholder="enc_ph_text" placeholder="Vertrauliche Notizen, Passwörter oder Anweisungen eingeben..."></textarea>
          </div>

          <!-- File Attachment Zone -->
          <div class="form-group">
            <label><span data-i18n="enc_label_file">Datei anhängen</span> <span class="hint" data-i18n="enc_hint_file">(Optional — vollständig durch Schlüssel verschlüsselt)</span></label>
            <input type="file" id="file-input" style="display: none;" onchange="handleFileSelected(event)">
            
            <div class="file-dropzone" id="file-dropzone" onclick="document.getElementById('file-input').click()">
              <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                <path d="M21.44 11.05l-9.19 9.19a6 6 0 0 1-8.49-8.49l9.19-9.19a4 4 0 0 1 5.66 5.66l-9.2 9.19a2 2 0 0 1-2.83-2.83l8.49-8.48"/>
              </svg>
              <div class="file-dropzone-text" data-i18n="dropzone_text">Klicken zum Auswählen oder Datei hierher ziehen</div>
              <div class="file-dropzone-hint" data-i18n="dropzone_hint">Dokumente, PDFs, Bilder, Archive — jedes Dateiformat</div>
            </div>

            <div class="attached-file-pill" id="attached-file-pill">
              <div class="attached-file-info">
                <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                  <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/>
                  <polyline points="14 2 14 8 20 8"/>
                </svg>
                <div>
                  <div class="attached-file-name" id="attached-file-name">filename.pdf</div>
                  <div class="attached-file-size" id="attached-file-size">0 KB</div>
                </div>
              </div>
              <button type="button" class="remove-file-btn" onclick="removeAttachedFile()" title="Remove file">✕</button>
            </div>
          </div>

          <div class="form-group" id="recipient-email-group">
            <label for="recipient-email">
              <span data-i18n="enc_label_email">Empfänger-E-Mail (Pflichtfeld)</span> <span style="color: var(--danger, #f85149); font-weight: 700;">*</span>
            </label>
            <input type="email" id="recipient-email" placeholder="recipient@example.com" required>
            <div id="enc-email-warning-box" style="margin-top: 6px; font-size: 12px; line-height: 1.45; color: #f85149; background: rgba(248, 81, 73, 0.1); border: 1px solid rgba(248, 81, 73, 0.25); border-radius: 6px; padding: 8px 10px; display: flex; align-items: flex-start; gap: 6px;">
              <span style="font-size: 14px; line-height: 1;">⚠️</span>
              <span id="enc-email-warning-text" data-i18n="enc_email_warning"><strong>Kryptographische Nachlass-Übergabe:</strong> Nach 30 Tagen Inaktivität wird Schlüssel B an diesen Empfänger gesendet. Das Abruffrontfenster beträgt anschließend 30 Tage, bevor alle Daten aus Datenschutzgründen unwiderruflich gelöscht werden.</span>
            </div>
          </div>

          <button class="btn-main" onclick="handleEncrypt()" data-i18n="btn_encrypt_save">Verschlüsseln & Speichern</button>

          <div id="enc-error" class="alert alert-error" style="margin-top: 14px;"></div>

          <div id="enc-results" class="result-box">
            <div class="alert alert-success">
              <div data-i18n="enc_success">Erfolgreich gespeichert. Auf diesem Gerät benötigen Sie zur Entschlüsselung nur den <strong>Speichercode</strong> und <strong>Schlüssel A</strong>.</div>
            </div>

            <div class="item-card">
              <div class="item-header">
                <span class="item-label" data-i18n="label_storage_code">Speichercode</span>
                <button class="btn-copy" onclick="copyText('res-code', this)" data-i18n="btn_copy">Kopieren</button>
              </div>
              <div id="res-code" class="item-code large"></div>
            </div>

            <div class="item-card">
              <div class="item-header">
                <span class="item-label" data-i18n="label_key_a">Ihr privater Schlüssel A</span>
                <button class="btn-copy" onclick="copyText('res-key-a', this)" data-i18n="btn_copy">Kopieren</button>
              </div>
              <div id="res-key-a" class="item-code"></div>
            </div>

            <div id="res-email-info" class="alert alert-success" style="display: none; margin-top: 8px;"></div>
          </div>
        </div>
      </div>

      <!-- 2. DECRYPT PANEL -->
      <div id="tab-decrypt" class="card" style="display: none;">
        <div class="card-header">
          <div class="card-title" data-i18n="dec_title">Daten & Dateien entschlüsseln</div>
          <div class="card-subtitle" data-i18n="dec_subtitle">Geben Sie Ihren Speichercode und Schlüssel A ein, um Ihre Daten abzurufen.</div>
        </div>

        <div class="form-group">
          <label for="dec-code" data-i18n="dec_label_code">Speichercode</label>
          <input type="text" id="dec-code" data-i18n-placeholder="dec_ph_code" placeholder="16-stelliger Code" maxlength="32">
        </div>

        <div class="form-group">
          <label for="dec-key-a" data-i18n="dec_label_key_a">Schlüssel A</label>
          <input type="text" id="dec-key-a" data-i18n-placeholder="dec_ph_key_a" placeholder="Schlüssel A einfügen...">
        </div>

        <div class="form-group">
          <label for="dec-key-b"><span data-i18n="dec_label_key_b">Schlüssel B</span> <span class="hint" data-i18n="dec_hint_key_b">(Nur nötig, wenn nicht als Eigentümer eingeloggt oder nach Nachlass)</span></label>
          <input type="text" id="dec-key-b" data-i18n-placeholder="dec_ph_key_b" placeholder="Auf eigenem Konto leer lassen...">
        </div>

        <button class="btn-main" onclick="handleDecrypt()" data-i18n="btn_decrypt">Entschlüsseln</button>

        <div id="dec-error" class="alert alert-error" style="margin-top: 14px;"></div>

        <div id="dec-results" class="result-box">
          
          <!-- Decrypted File Download Card -->
          <div id="dec-file-section" style="display: none;" class="decrypted-file-card">
            <div class="attached-file-info">
              <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/>
                <polyline points="14 2 14 8 20 8"/>
              </svg>
              <div>
                <div class="attached-file-name" id="dec-file-name">document.pdf</div>
                <div class="attached-file-size" id="dec-file-size">1.2 MB</div>
              </div>
            </div>
            <button type="button" class="btn-download" id="dec-download-btn" onclick="downloadDecryptedFile()">
              <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round">
                <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/>
                <polyline points="7 10 12 15 17 10"/>
                <line x1="12" y1="15" x2="12" y2="3"/>
              </svg>
              <span data-i18n="btn_download_file">Datei herunterladen</span>
            </button>
          </div>

          <!-- Decrypted Text Card -->
          <div id="dec-text-section" style="display: none;" class="item-card">
            <div class="item-header">
              <span class="item-label" data-i18n="label_dec_text">Entschlüsselter Text</span>
              <button class="btn-copy" onclick="copyText('res-decrypted', this)" data-i18n="btn_copy">Kopieren</button>
            </div>
            <div id="res-decrypted" class="item-code" style="white-space: pre-wrap; font-size: 13.5px;"></div>
          </div>

          <!-- Decrypted Vault / File Management Actions -->
          <div id="dec-actions-section" style="display: none; margin-top: 14px; padding-top: 12px; border-top: 1px solid var(--border); justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 8px;">
            <span style="font-size: 11.5px; color: var(--text-muted);" data-i18n="dec_manage_hint">Verwaltung:</span>
            <button type="button" class="btn-vault-action danger" id="dec-delete-btn" onclick="openDeleteModalForDecrypted()" style="padding: 7px 14px; font-size: 12px; display: inline-flex; align-items: center; gap: 5px;">
              🗑️ <span data-i18n="btn_delete_vault_file">Datei & Tresor vom Server löschen</span>
            </button>
          </div>
        </div>
      </div>

      <!-- 3. INHERITANCE PANEL -->
      <div id="tab-inherit" class="card" style="display: none;">
        <div class="card-header">
          <div class="card-title" data-i18n="inh_title">Nachlass übergeben (Vererbung)</div>
          <div class="card-subtitle" data-i18n="inh_subtitle">Gibt Schlüssel B an den Empfänger frei und löscht ihn vom Server.</div>
        </div>

        <div class="alert alert-warning">
          <div data-i18n="inh_warning"><strong>Automatisierte Notfallübergabe:</strong> Erfolgt 30 Tage lang keine Aktivität, wird Schlüssel B an den hinterlegten Empfänger übermittelt. Nach erfolgter Übergabe oder Trennung der Verbindung verbleiben 30 Tage zum Abruf, bevor alle Daten unwiderruflich gelöscht werden.</div>
        </div>

        <div class="form-group">
          <label for="inh-code" data-i18n="dec_label_code">Speichercode</label>
          <input type="text" id="inh-code" data-i18n-placeholder="dec_ph_code" placeholder="16-stelliger Code" maxlength="32">
        </div>

        <div class="form-group">
          <label for="inh-key-a" data-i18n="label_inh_key_a">Schlüssel A (zur Autorisierung)</label>
          <input type="text" id="inh-key-a" data-i18n-placeholder="dec_ph_key_a" placeholder="Schlüssel A einfügen...">
        </div>

        <div style="display: flex; gap: 10px; flex-wrap: wrap; margin-top: 6px;">
          <button class="btn-main" style="flex: 1; min-width: 200px;" onclick="handleInherit()" data-i18n="btn_inherit">🚀 Nachlass jetzt ausführen</button>
          <button class="btn-main" style="flex: 1; min-width: 200px; background: #6e7681; border: 1px solid var(--border);" onclick="handleStopInheritance()" data-i18n="btn_stop_inherit">🛑 Nachlass dauerhaft stoppen</button>
        </div>

        <div id="inh-error" class="alert alert-error" style="margin-top: 14px;"></div>

        <div id="inh-results" class="result-box">
          <div id="inh-alert-status" class="alert alert-success" style="display: none;"></div>

          <div id="inh-key-field" class="item-card" style="display: none; margin-top: 8px;">
            <div class="item-header">
              <span class="item-label" data-i18n="label_released_key_b">Freigegebener Schlüssel B</span>
              <button class="btn-copy" onclick="copyText('res-key-b', this)" data-i18n="btn_copy">Kopieren</button>
            </div>
            <div id="res-key-b" class="item-code"></div>
          </div>
        </div>
      </div>

      <!-- 4. MY VAULTS PANEL -->
      <div id="tab-vaults" class="card" style="display: none;">
        <div class="card-header vaults-header-bar">
          <div>
            <div class="card-title" data-i18n="vaults_title">Meine Tresore & Verwahrungen</div>
            <div class="card-subtitle" data-i18n="vaults_subtitle">Übersicht aller von Ihrem Konto verschlüsselten Dateien, Texte und Nachlässe.</div>
          </div>
          <button class="btn-auth-nav" onclick="loadUserVaults()" title="Aktualisieren">↻ <span data-i18n="vaults_refresh">Aktualisieren</span></button>
        </div>

        <!-- Auth Guard if Logged Out -->
        <div id="auth-guard-vaults" class="guard-card" style="display: none;">
          <div class="guard-icon">🔐</div>
          <div class="guard-title" data-i18n="auth_guard_title">Anmeldung erforderlich</div>
          <div class="guard-desc" data-i18n="auth_guard_desc">Um Ihre gespeicherten Tresore einzusehen, müssen Sie angemeldet sein.</div>
          <button class="btn-main" style="max-width: 260px; margin: 0 auto;" onclick="openAuthModal('login')" data-i18n="auth_guard_btn">Jetzt anmelden / registrieren</button>
        </div>

        <!-- Content Box (visible when logged in) -->
        <div id="vaults-content-box">
          <div id="vaults-loading" style="text-align: center; padding: 24px; color: var(--text-muted);">
            Lade Ihre Tresore...
          </div>
          <div id="vaults-empty" style="display: none; text-align: center; padding: 28px 16px; color: var(--text-muted);">
            <div style="font-size: 28px; margin-bottom: 8px;">📂</div>
            <div style="font-size: 13px; font-weight: 600;" data-i18n="vaults_empty">Sie haben aktuell noch keine Daten verschlüsselt.</div>
            <button class="btn-main" style="margin-top: 14px; max-width: 240px; margin-left: auto; margin-right: auto;" onclick="switchTab('encrypt')" data-i18n="vaults_btn_encrypt_now">Jetzt ersten Tresor erstellen</button>
          </div>
          <div id="user-vaults-list" class="vaults-list" style="display: none;"></div>
        </div>
      </div>

    </div>

    <footer>
      <span data-i18n="footer_text">SecureVault • Zero-Knowledge Dead Man's Switch • Schweiz</span>
    </footer>
  </div>

  <script>
    const I18N = {
      de: {
        nav_overview: "Übersicht",
        nav_encrypt: "Verschlüsseln",
        nav_decrypt: "Entschlüsseln",
        nav_inherit: "Vererbung",
        nav_vaults: "Meine Tresore",
        nav_info: "Info",
        nav_login: "Anmelden",
        nav_register: "Registrieren",
        nav_logout: "Abmelden",
        
        hero_title: "Zero-Knowledge Tresor & Kryptographischer Nachlass",
        hero_desc: "Sichere Verwahrung vertraulicher Dokumente und digitaler Nachlässe. SecureVault ist auf die zeitgesteuerte Notfallübergabe ausgelegt: 30 Tage nach Freigabe des Schlüssels an den Empfänger wird der Datensatz aus Sicherheitsgründen vollständig und unwiderruflich gelöscht.",
        btn_open_vault: "Tresor öffnen →",
        btn_more_info: "Mehr Informationen",
        
        hl1_title: "Dual-Key Split (256-Bit)",
        hl1_desc: "Weder Schlüssel A noch B allein kann entschlüsseln.",
        hl2_title: "Schweizer Zero-Knowledge",
        hl2_desc: "Server speichert 0 KB Klartext. Vollständige Vertraulichkeit.",
        hl3_title: "Dead Man's Switch & Datenlöschung",
        hl3_desc: "Schlüsselübergabe bei Inaktivität. Vollständige Löschung 30 Tage nach Freigabe.",
        
        modal_title: "Funktionsweise & Architektur",
        flow_title: "Kryptographische Verwahrungs-Pipeline",
        step1_title: "Geheimnis eingeben",
        step1_desc: "Text erfassen oder vertrauliche Dokumente anhängen.",
        step2_title: "Split-Key Aufteilung",
        step2_desc: "Erzeugung voneinander unabhängiger 256-Bit Schlüssel A und B.",
        step3_title: "Zero-Knowledge",
        step3_desc: "Ende-zu-Ende-Verschlüsselung direkt im Browser vor dem Speichern.",
        step4_title: "Abrufen / Nachlass",
        step4_desc: "Direkte Geräte-Entschlüsselung oder Notfallübergabe mit 30-Tage-Abruffrist.",
        
        feat1_title: "Dual-Key Split (256-Bit)",
        feat1_desc: "Jeder Datensatz wird in zwei kryptographische Teilschlüssel (A & B) aufgeteilt. Nur die Kombination beider Schlüssel ermöglicht die Entschlüsselung.",
        feat2_title: "Kontogebundene Primärnutzung",
        feat2_desc: "Auf Ihrem autorisierten Benutzerkonto wird Schlüssel B automatisch angewendet. Sie benötigen zur Entschlüsselung lediglich Ihren Speichercode und Schlüssel A.",
        feat3_title: "30-Tage Inaktivitäts-Nachlass & Automatische Löschung",
        feat3_desc: "Erfolgt 30 Tage lang keine Aktivität, wird Schlüssel B automatisch an den hinterlegten Empfänger übermittelt. Zum Schutz der Privatsphäre werden alle verschlüsselten Daten 30 Tage nach der Übergabe unwiderruflich vom Server entfernt.",
        feat4_title: "Verschlüsselte Dateianhänge",
        feat4_desc: "Vertrauliche PDFs, Dokumente oder Nachweise anhängen – mit direkter Entschlüsselung und Download im Browser.",
        feat5_title: "Zero-Knowledge Architektur",
        feat5_desc: "Dateiinhalte, Texte und Metadaten werden vor der Übertragung verschlüsselt. Der Server besitzt zu keinem Zeitpunkt Einsicht in Ihre Daten.",
        feat6_title: "Schweizer Datenschutz & Standort",
        feat6_desc: "Betrieben nach strengen Schweizer Datenschutzstandards. Höchste Privatsphäre ohne Tracker und ohne Telemetrie.",
        
        spec_enc: "Verschlüsselung:",
        spec_split: "Key-Split:",
        spec_plain: "Klartext:",
        spec_plain_val: "0 KB gespeichert",
        spec_inactivity: "Inaktivität:",
        spec_inactivity_val: "30 Tage",
        spec_juris: "Standort:",
        spec_juris_val: "Schweiz",
        
        tab_encrypt: "Verschlüsseln",
        tab_decrypt: "Entschlüsseln",
        tab_inherit: "Vererbung",
        
        auth_modal_title_login: "Bei SecureVault anmelden",
        auth_modal_title_register: "Neues Konto erstellen",
        auth_tab_login: "Anmelden",
        auth_tab_register: "Registrieren",
        auth_label_username: "Benutzername",
        auth_ph_username: "z.B. max_muster",
        auth_label_password: "Passwort",
        auth_ph_password: "••••••••",
        auth_label_password_confirm: "Passwort bestätigen",
        auth_btn_login: "Anmelden",
        auth_btn_register: "Konto erstellen",
        auth_toggle_to_register: "Noch kein Konto? Jetzt registrieren →",
        auth_toggle_to_login: "Bereits registriert? Jetzt anmelden →",
        auth_guard_title: "Anmeldung erforderlich",
        auth_guard_desc: "Um vertrauliche Daten und Dateien zu verschlüsseln oder Ihre gespeicherten Tresore einzusehen, müssen Sie angemeldet sein.",
        auth_guard_btn: "Jetzt anmelden / registrieren",
        
        vaults_title: "Meine Tresore & Verwahrungen",
        vaults_subtitle: "Übersicht aller von Ihrem Konto verschlüsselten Dateien, Texte und Nachlässe.",
        vaults_empty: "Sie haben aktuell noch keine Daten verschlüsselt.",
        vaults_btn_encrypt_now: "Jetzt ersten Tresor erstellen",
        vaults_refresh: "Aktualisieren",
        
        enc_title: "Daten & Dokumente verschlüsseln",
        enc_subtitle: "Zero-Knowledge Dual-Key-Split. Der Server hat keinerlei Zugriff auf Ihre Inhalte.",
        enc_label_text: "Vertrauliche Notizen / Daten",
        enc_hint_text: "(Optional bei Dateianhang)",
        enc_ph_text: "Vertrauliche Informationen, Zugangsdaten oder Anweisungen eingeben...",
        enc_label_file: "Datei anhängen",
        enc_hint_file: "(Optional — Ende-zu-Ende verschlüsselt)",
        dropzone_text: "Klicken zum Auswählen oder Datei hierher ziehen",
        dropzone_hint: "Dokumente, PDFs, Bilder, Archive — jedes Dateiformat",
        enc_label_email: "Empfänger-E-Mail für Notfallübergabe (Pflichtfeld)",
        enc_email_warning: "<strong>Kryptographische Nachlass-Übergabe:</strong> Nach 30 Tagen Inaktivität wird Schlüssel B an diesen Empfänger gesendet. Das Abruffrontfenster beträgt anschließend 30 Tage, bevor alle Daten aus Datenschutzgründen unwiderruflich gelöscht werden.",
        btn_encrypt_save: "Verschlüsseln & Speichern",
        enc_success: "Erfolgreich gespeichert. Auf Ihrem Konto benötigen Sie zur Entschlüsselung nur den <strong>Speichercode</strong> und <strong>Schlüssel A</strong>.",
        label_storage_code: "Speichercode",
        label_key_a: "Ihr privater Schlüssel A",
        
        dec_title: "Daten & Dokumente entschlüsseln",
        dec_subtitle: "Geben Sie Ihren Speichercode und Schlüssel A ein, um Ihre Daten abzurufen.",
        dec_label_code: "Speichercode",
        dec_ph_code: "16-stelliger Code",
        dec_label_key_a: "Schlüssel A",
        dec_ph_key_a: "Schlüssel A einfügen...",
        dec_label_key_b: "Schlüssel B",
        dec_hint_key_b: "(Nur nötig, wenn nicht als Eigentümer eingeloggt oder nach Nachlass)",
        dec_ph_key_b: "Auf eigenem Konto leer lassen...",
        btn_decrypt: "Entschlüsseln",
        btn_download_file: "Datei herunterladen",
        label_dec_text: "Entschlüsselter Text",
        
        inh_title: "Nachlass übergeben (Vererbung)",
        inh_subtitle: "Gibt Schlüssel B an den Empfänger frei oder beendet die automatisierte Weitergabe.",
        inh_warning: "<strong>Automatisierte Notfallübergabe:</strong> Erfolgt 30 Tage lang keine Aktivität, wird Schlüssel B an den hinterlegten Empfänger übermittelt. Nach erfolgter Übergabe oder Trennung der Verbindung verbleiben 30 Tage zum Abruf, bevor alle Daten unwiderruflich gelöscht werden.",
        label_inh_key_a: "Schlüssel A (zur Autorisierung)",
        btn_inherit: "🚀 Nachlass jetzt übergeben",
        btn_stop_inherit: "🛑 Nachlass dauerhaft stoppen",
        inh_success: "<strong>Nachlassübergabe ausgelöst:</strong> Schlüssel B wurde versendet und vom Server gelöscht. ⚠️ <strong>30-Tage-Abruffrist:</strong> Der Empfänger hat 30 Tage Zeit zum Abruf der Daten, bevor der Datensatz unwiderruflich gelöscht wird.",
        inh_stopped_success: "<strong>Nachlassverbindung getrennt:</strong> Die automatische Weitergabe wurde deaktiviert. ⚠️ <strong>30-Tage-Löschfrist:</strong> Nach Trennung der Verbindung verbleiben 30 Tage zum Abruf, bevor die Daten vollständig vom Server gelöscht werden.",
        label_released_key_b: "Freigegebener Schlüssel B",
        
        btn_delete_vault_file: "Datei & Tresor vom Server löschen",
        dec_manage_hint: "Verwaltung:",
        delete_modal_title: "Tresor & Datei endgültig löschen?",
        delete_modal_text_prefix: "Möchten Sie den Datensatz mit Code",
        delete_modal_text_suffix: "und alle darin verschlüsselten Dateien wirklich unwiderruflich vom Server löschen?",
        delete_modal_warning: "Diese Aktion kann nicht rückgängig gemacht werden. Der Datensatz und alle Dateien werden sofort und vollständig aus dem Serverspeicher entfernt.",
        delete_modal_cancel: "Abbrechen",
        delete_modal_confirm: "🗑️ Unwiderruflich löschen",
        delete_success_msg: "Tresor & Datei wurden erfolgreich und unwiderruflich vom Server gelöscht.",
        
        btn_copy: "Kopieren",
        btn_copied: "Kopiert",
        footer_text: "SecureVault • Zero-Knowledge Dead Man's Switch • Schweiz",
        
        err_fill_payload: "Bitte Text eingeben oder eine Datei anhängen.",
        err_code_key_req: "Sowohl der Speichercode sowie Schlüssel A sind erforderlich.",
        err_code_req: "Bitte den 16-stelligen Speichercode eingeben.",
        err_email_req: "Bitte eine gültige Empfänger-E-Mail-Adresse eingeben (Pflichtfeld zur Notfallübergabe).",
        err_pwd_mismatch: "Die Passwörter stimmen nicht überein."
      },
      en: {
        nav_overview: "Overview",
        nav_encrypt: "Encrypt",
        nav_decrypt: "Decrypt",
        nav_inherit: "Inheritance",
        nav_vaults: "My Vaults",
        nav_info: "Info",
        nav_login: "Sign In",
        nav_register: "Register",
        nav_logout: "Sign Out",
        
        hero_title: "Zero-Knowledge Digital Vault & Dead Man's Switch",
        hero_desc: "Cryptographic emergency custody for confidential files and digital inheritances. SecureVault is engineered for automated emergency handover: all encrypted data is permanently purged 30 days following key release.",
        btn_open_vault: "Open Vault →",
        btn_more_info: "More Information",
        
        hl1_title: "Dual-Key Split (256-Bit)",
        hl1_desc: "Neither Key A nor Key B alone can decrypt.",
        hl2_title: "Swiss Zero-Knowledge",
        hl2_desc: "Server stores 0 KB plaintext. Absolute confidentiality.",
        hl3_title: "Dead Man's Switch & Auto-Purge",
        hl3_desc: "Key release upon inactivity. Data permanently purged 30 days after handover.",
        
        modal_title: "Architecture & How It Works",
        flow_title: "Cryptographic Custody Pipeline",
        step1_title: "Input Secret",
        step1_desc: "Type confidential text or attach sensitive documents.",
        step2_title: "Split-Key Generation",
        step2_desc: "Generation of independent 256-bit Key A and Key B.",
        step3_title: "Zero-Knowledge Encryption",
        step3_desc: "End-to-end client-side encryption in browser memory before storage.",
        step4_title: "Retrieval / Handover",
        step4_desc: "Instant device decryption or heir handover with a 30-day retrieval window.",
        
        feat1_title: "Dual-Key Split (256-Bit)",
        feat1_desc: "Every record is partitioned into two cryptographic key shares (A & B). Only their combination unlocks the original data.",
        feat2_title: "Account-Bound Seamless Decryption",
        feat2_desc: "On your authenticated account, Key B is auto-applied seamlessly. You only need your Storage Code and Key A to decrypt.",
        feat3_title: "30-Day Inactivity Switch & 30-Day Auto-Purge",
        feat3_desc: "If no owner activity is registered for 30 days, Key B is automatically dispatched to the designated recipient. To safeguard privacy, all encrypted data is permanently deleted 30 days after handover.",
        feat4_title: "Encrypted File Attachments",
        feat4_desc: "Attach sensitive PDFs, documents, or credentials with 1-click in-browser decryption and direct download.",
        feat5_title: "Zero-Knowledge Storage",
        feat5_desc: "File payloads, notes, and metadata are encrypted prior to transmission. Server operators have zero visibility into your data.",
        feat6_title: "Swiss Privacy & Jurisdiction",
        feat6_desc: "Operated under strict Swiss data protection principles. Completely private with zero trackers and zero telemetry.",
        
        spec_enc: "Encryption:",
        spec_split: "Key Split:",
        spec_plain: "Plaintext:",
        spec_plain_val: "0 KB Stored",
        spec_inactivity: "Inactivity:",
        spec_inactivity_val: "30 Days",
        spec_juris: "Jurisdiction:",
        spec_juris_val: "Switzerland",
        
        tab_encrypt: "Encrypt",
        tab_decrypt: "Decrypt",
        tab_inherit: "Inheritance",
        
        auth_modal_title_login: "Sign in to SecureVault",
        auth_modal_title_register: "Create a Secure Account",
        auth_tab_login: "Sign In",
        auth_tab_register: "Register",
        auth_label_username: "Username",
        auth_ph_username: "e.g. alice",
        auth_label_password: "Password",
        auth_ph_password: "••••••••",
        auth_label_password_confirm: "Confirm Password",
        auth_btn_login: "Sign In",
        auth_btn_register: "Create Account",
        auth_toggle_to_register: "Don't have an account? Register now →",
        auth_toggle_to_login: "Already have an account? Sign in →",
        auth_guard_title: "Authentication Required",
        auth_guard_desc: "Please sign in or register to encrypt new data and view your personal vaults.",
        auth_guard_btn: "Sign In / Register",
        
        vaults_title: "My Vaults & Records",
        vaults_subtitle: "Complete overview of all encrypted files, notes, and handovers stored under your account.",
        vaults_empty: "You have not encrypted any records yet.",
        vaults_btn_encrypt_now: "Create First Vault",
        vaults_refresh: "Refresh",
        
        enc_title: "Encrypt Data & Documents",
        enc_subtitle: "Client-side Dual-Key Split. The server cannot inspect or access your data.",
        enc_label_text: "Confidential Notes / Information",
        enc_hint_text: "(Optional if attaching a file)",
        enc_ph_text: "Enter sensitive notes, credentials, or instructions...",
        enc_label_file: "Attach File",
        enc_hint_file: "(Optional — end-to-end encrypted)",
        dropzone_text: "Click to choose a file or drag & drop",
        dropzone_hint: "Documents, PDFs, Images, Archives — any file format",
        enc_label_email: "Recipient Email for Emergency Handover (Required)",
        enc_email_warning: "<strong>Cryptographic Inheritance Handover:</strong> After 30 days of inactivity, Key B is automatically dispatched to this recipient. A 30-day retrieval window then commences, after which all data is permanently purged for privacy.",
        btn_encrypt_save: "Encrypt & Save",
        enc_success: "Saved successfully. Under your account, you only need the <strong>Storage Code</strong> and <strong>Key A</strong> to decrypt.",
        label_storage_code: "Storage Code",
        label_key_a: "Your Key A",
        
        dec_title: "Decrypt Data & Documents",
        dec_subtitle: "Enter your Storage Code and Key A to retrieve your decrypted information.",
        dec_label_code: "Storage Code",
        dec_ph_code: "16-character code",
        dec_label_key_a: "Key A",
        dec_ph_key_a: "Paste Key A...",
        dec_label_key_b: "Key B",
        dec_hint_key_b: "(Only needed if not signed into owner account or following inheritance handover)",
        dec_ph_key_b: "Leave empty if logged into owner account...",
        btn_decrypt: "Decrypt",
        btn_download_file: "Download File",
        label_dec_text: "Decrypted Text",
        
        inh_title: "Transfer Custody (Inheritance)",
        inh_subtitle: "Releases Key B to the recipient or stops automated handover.",
        inh_warning: "<strong>Automated Custody Handover:</strong> If no activity is registered for 30 days, Key B is dispatched to the designated recipient. A 30-day retrieval window begins upon transfer, after which all encrypted data is permanently deleted.",
        label_inh_key_a: "Key A (for Authorization)",
        btn_inherit: "🚀 Transfer Custody Now",
        btn_stop_inherit: "🛑 Stop Auto-Inheritance Permanently",
        inh_success: "<strong>Custody Handover Executed:</strong> Key B has been dispatched and removed from server memory. ⚠️ <strong>30-Day Retrieval Window:</strong> The recipient has 30 days to retrieve the data before the record is permanently deleted.",
        inh_stopped_success: "<strong>Dead Man Switch Disconnected:</strong> Automated handover has been disabled. ⚠️ <strong>30-Day Purge Window:</strong> Following disconnection, you have 30 days to retrieve your data before it is permanently deleted from the server.",
        label_released_key_b: "Released Key B",
        
        btn_delete_vault_file: "Delete File & Vault from Server",
        dec_manage_hint: "Management:",
        delete_modal_title: "Permanently Delete Vault & File?",
        delete_modal_text_prefix: "Are you sure you want to permanently delete vault with code",
        delete_modal_text_suffix: "and all contained encrypted files from the server?",
        delete_modal_warning: "This action cannot be undone. The record and files will be immediately erased from server storage.",
        delete_modal_cancel: "Cancel",
        delete_modal_confirm: "🗑️ Delete Permanently",
        delete_success_msg: "Vault and file were permanently deleted from the server.",
        
        btn_copy: "Copy",
        btn_copied: "Copied",
        footer_text: "SecureVault • Zero-Knowledge Dead Man's Switch • Switzerland",
        
        err_fill_payload: "Please enter text or attach a file to encrypt.",
        err_code_key_req: "Both the Storage Code and Key A are required.",
        err_code_req: "Please enter the 16-character Storage Code.",
        err_email_req: "Please enter a valid recipient email address (Required for emergency handover).",
        err_pwd_mismatch: "Passwords do not match."
      }
    };

    let currentLang = 'de';
    let currentUser = null;
    let authMode = 'login';
    let selectedFileObject = null;
    let decryptedFileObject = null;

    function openInfoModal() {
      document.getElementById('info-modal').style.display = 'flex';
    }

    function closeInfoModal() {
      document.getElementById('info-modal').style.display = 'none';
    }

    function closeInfoModalOnBackdrop(e) {
      if (e.target.id === 'info-modal') closeInfoModal();
    }

    /* Auth Modal Management */
    function openAuthModal(mode) {
      switchAuthMode(mode || 'login');
      document.getElementById('auth-modal').style.display = 'flex';
      setTimeout(() => document.getElementById('auth-username').focus(), 100);
    }

    function closeAuthModal() {
      document.getElementById('auth-modal').style.display = 'none';
      document.getElementById('auth-error').style.display = 'none';
      document.getElementById('auth-success').style.display = 'none';
    }

    function closeAuthModalOnBackdrop(e) {
      if (e.target.id === 'auth-modal') closeAuthModal();
    }

    function switchAuthMode(mode) {
      authMode = mode;
      const isLogin = mode === 'login';
      document.getElementById('auth-tab-login').classList.toggle('active', isLogin);
      document.getElementById('auth-tab-register').classList.toggle('active', !isLogin);
      document.getElementById('auth-confirm-group').style.display = isLogin ? 'none' : 'block';
      document.getElementById('auth-modal-title').textContent = isLogin
        ? (I18N[currentLang].auth_modal_title_login || 'Bei SecureVault anmelden')
        : (I18N[currentLang].auth_modal_title_register || 'Neues Konto erstellen');
      document.getElementById('auth-submit-btn').textContent = isLogin
        ? (I18N[currentLang].auth_btn_login || 'Anmelden')
        : (I18N[currentLang].auth_btn_register || 'Konto erstellen');
      document.getElementById('auth-toggle-link').textContent = isLogin
        ? (I18N[currentLang].auth_toggle_to_register || 'Noch kein Konto? Jetzt registrieren →')
        : (I18N[currentLang].auth_toggle_to_login || 'Bereits registriert? Jetzt anmelden →');
      document.getElementById('auth-error').style.display = 'none';
      document.getElementById('auth-success').style.display = 'none';
    }

    function toggleAuthMode() {
      switchAuthMode(authMode === 'login' ? 'register' : 'login');
    }

    async function handleAuthSubmit(e) {
      e.preventDefault();
      const username = document.getElementById('auth-username').value.trim();
      const password = document.getElementById('auth-password').value;
      const confirmPwd = document.getElementById('auth-password-confirm').value;
      const errBox = document.getElementById('auth-error');
      const succBox = document.getElementById('auth-success');
      errBox.style.display = 'none';
      succBox.style.display = 'none';

      if (authMode === 'register' && password !== confirmPwd) {
        errBox.textContent = I18N[currentLang].err_pwd_mismatch || 'Die Passwörter stimmen nicht überein.';
        errBox.style.display = 'block';
        return;
      }

      const endpoint = authMode === 'register' ? '/api/register' : '/api/login';
      try {
        const res = await fetch(endpoint, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ username, password })
        });
        const data = await res.json();
        if (!res.ok) throw new Error(data.error || 'Authentication failed.');

        currentUser = data.username;
        if (data.token) {
          localStorage.setItem('sv_auth_token', data.token);
        }
        succBox.textContent = data.message || 'Success';
        succBox.style.display = 'block';
        setTimeout(() => {
          closeAuthModal();
          checkAuthStatus();
        }, 500);
      } catch (err) {
        errBox.textContent = err.message;
        errBox.style.display = 'block';
      }
    }

    async function handleLogout() {
      try {
        await fetch('/api/logout', { method: 'POST' });
      } catch (e) {}
      localStorage.removeItem('sv_auth_token');
      currentUser = null;
      checkAuthStatus();
      navigateTo('home');
    }

    async function checkAuthStatus() {
      try {
        const token = localStorage.getItem('sv_auth_token');
        const headers = token ? { 'Authorization': 'Bearer ' + token } : {};
        const res = await fetch('/api/me', { headers });
        const data = await res.json();
        if (data.authenticated && data.username) {
          currentUser = data.username;
          document.getElementById('nav-auth-logged-out').style.display = 'none';
          document.getElementById('nav-auth-logged-in').style.display = 'flex';
          document.getElementById('nav-username').textContent = currentUser;
          document.getElementById('tab-btn-vaults').style.display = 'flex';
          
          document.getElementById('auth-guard-encrypt').style.display = 'none';
          document.getElementById('enc-form-container').style.display = 'block';

          document.getElementById('auth-guard-vaults').style.display = 'none';
          document.getElementById('vaults-content-box').style.display = 'block';
        } else {
          currentUser = null;
          document.getElementById('nav-auth-logged-out').style.display = 'flex';
          document.getElementById('nav-auth-logged-in').style.display = 'none';
          document.getElementById('tab-btn-vaults').style.display = 'none';

          document.getElementById('auth-guard-encrypt').style.display = 'block';
          document.getElementById('enc-form-container').style.display = 'none';

          document.getElementById('auth-guard-vaults').style.display = 'block';
          document.getElementById('vaults-content-box').style.display = 'none';
        }
      } catch (e) {
        currentUser = null;
      }
    }

    async function loadUserVaults() {
      if (!currentUser) return;
      const loading = document.getElementById('vaults-loading');
      const emptyBox = document.getElementById('vaults-empty');
      const list = document.getElementById('user-vaults-list');
      loading.style.display = 'block';
      emptyBox.style.display = 'none';
      list.style.display = 'none';

      try {
        const token = localStorage.getItem('sv_auth_token');
        const headers = token ? { 'Authorization': 'Bearer ' + token } : {};
        const res = await fetch('/api/my-vaults', { headers });
        const data = await res.json();
        loading.style.display = 'none';

        if (!res.ok) throw new Error(data.error || 'Failed to load vaults');

        const vaults = data.vaults || [];
        const countBadge = document.getElementById('vault-count');
        if (countBadge) {
          countBadge.textContent = vaults.length;
          countBadge.style.display = vaults.length > 0 ? 'inline-block' : 'none';
        }

        if (vaults.length === 0) {
          emptyBox.style.display = 'block';
          return;
        }

        list.innerHTML = '';
        vaults.forEach(v => {
          const item = document.createElement('div');
          item.className = 'vault-item-card';

          let statusClass = 'active';
          let statusText = currentLang === 'de' ? 'Aktiv (Geschützt)' : 'Active (Secured)';
          let metaHtml = '';
          const recipient = v.has_recipient_email 
            ? (currentLang === 'de' ? '✉️ Empfänger hinterlegt' : '✉️ Recipient registered')
            : '—';

          if (v.mode === 'inherited') {
            statusClass = 'inherited';
            statusText = currentLang === 'de' ? 'Nachlass ausgelöst' : 'Inherited Mode';
            metaHtml = `
              <span class="vault-meta-item">📧 <strong>${recipient}</strong></span>
              <span class="vault-meta-item" style="color: #d29922;">⚠️ <strong>${currentLang === 'de' ? 'Schlüssel B übergeben' : 'Key B released'}</strong></span>
            `;
          } else if (v.mode === 'stopped') {
            statusClass = 'stopped';
            statusText = currentLang === 'de' ? 'Verbindung getrennt' : 'Disconnected';
            metaHtml = `
              <span class="vault-meta-item">🛑 <strong>${currentLang === 'de' ? 'Notfallweitergabe deaktiviert' : 'Handover disabled'}</strong></span>
            `;
          } else {
            // Normal mode: Active vault on logged-in account
            metaHtml = `
              <span class="vault-meta-item">🛡️ <strong>${currentLang === 'de' ? 'Dead-Man-Switch: 30 Tage Inaktivitäts-Intervall' : 'Dead-Man-Switch: 30-Day Inactivity Interval'}</strong></span>
              <span class="vault-meta-item">📧 <strong>${recipient}</strong></span>
            `;
          }

          item.innerHTML = `
            <div class="vault-card-top">
              <span class="vault-code-tag">${v.code}</span>
              <span class="status-pill ${statusClass}">${statusText}</span>
            </div>
            <div class="vault-meta-row">
              ${metaHtml}
            </div>
            <div class="vault-actions-row">
              <button class="btn-vault-action primary" onclick="openDecryptForCode('${v.code}')">🔓 ${currentLang === 'de' ? 'Entschlüsseln' : 'Decrypt'}</button>
              ${v.mode === 'normal' ? `
                <button class="btn-vault-action" onclick="openInheritForCode('${v.code}')">🚀 ${currentLang === 'de' ? 'Nachlass auslösen' : 'Trigger Handover'}</button>
                <button class="btn-vault-action danger" onclick="openStopInheritForCode('${v.code}')">🛑 ${currentLang === 'de' ? 'Verbindung trennen' : 'Disconnect'}</button>
              ` : ''}
              <button class="btn-vault-action danger" onclick="openDeleteModal('${v.code}')">🗑️ ${currentLang === 'de' ? 'Löschen' : 'Delete'}</button>
            </div>
          `;
          list.appendChild(item);
        });

        list.style.display = 'flex';
      } catch (err) {
        loading.style.display = 'none';
        list.innerHTML = `<div class="alert alert-error" style="display:block;">${err.message}</div>`;
        list.style.display = 'block';
      }
    }

    let pendingDeleteCode = null;
    let pendingDeleteKeyA = null;
    let currentDecryptedCode = null;
    let currentDecryptedKeyA = null;

    function openDeleteModal(code, keyA) {
      pendingDeleteCode = code;
      pendingDeleteKeyA = keyA || null;
      const codeDisplay = document.getElementById('delete-modal-code-display');
      if (codeDisplay) codeDisplay.textContent = code;
      const errBox = document.getElementById('delete-modal-error');
      if (errBox) errBox.style.display = 'none';
      document.getElementById('delete-modal').style.display = 'flex';
    }

    function openDeleteModalForDecrypted() {
      const code = document.getElementById('dec-code').value.trim() || currentDecryptedCode;
      const keyA = document.getElementById('dec-key-a').value.trim() || currentDecryptedKeyA;
      if (!code) return;
      openDeleteModal(code, keyA);
    }

    function closeDeleteModal() {
      pendingDeleteCode = null;
      pendingDeleteKeyA = null;
      document.getElementById('delete-modal').style.display = 'none';
    }

    function closeDeleteModalOnBackdrop(e) {
      if (e.target.id === 'delete-modal') {
        closeDeleteModal();
      }
    }

    async function executeDeleteVault() {
      if (!pendingDeleteCode) return;
      const errBox = document.getElementById('delete-modal-error');
      const confirmBtn = document.getElementById('delete-modal-confirm-btn');
      if (errBox) errBox.style.display = 'none';
      if (confirmBtn) {
        confirmBtn.disabled = true;
        confirmBtn.textContent = currentLang === 'de' ? 'Lösche...' : 'Deleting...';
      }

      try {
        const token = localStorage.getItem('sv_auth_token');
        const headers = { 'Content-Type': 'application/json' };
        if (token) headers['Authorization'] = 'Bearer ' + token;

        const payload = { code: pendingDeleteCode };
        if (pendingDeleteKeyA) payload.key_a = pendingDeleteKeyA;

        const res = await fetch('/api/delete-vault', {
          method: 'POST',
          headers: headers,
          body: JSON.stringify(payload)
        });
        const data = await res.json();
        if (!res.ok) throw new Error(data.error || 'Deletion failed.');

        const deletedCode = pendingDeleteCode;
        closeDeleteModal();

        // If currently decrypted with this code, clear and notify
        if (currentDecryptedCode === deletedCode || document.getElementById('dec-code').value.trim() === deletedCode) {
          document.getElementById('dec-results').style.display = 'none';
          document.getElementById('dec-code').value = '';
          document.getElementById('dec-key-a').value = '';
          document.getElementById('dec-key-b').value = '';
          currentDecryptedCode = null;
          currentDecryptedKeyA = null;
          const decErr = document.getElementById('dec-error');
          decErr.className = 'alert alert-success';
          decErr.innerHTML = `🗑️ ${I18N[currentLang].delete_success_msg || 'Tresor & Datei wurden erfolgreich und unwiderruflich vom Server gelöscht.'}`;
          decErr.style.display = 'block';
        }

        // If user logged in, reload vault list
        if (currentUser) {
          loadUserVaults();
        }
      } catch (err) {
        if (errBox) {
          errBox.textContent = err.message;
          errBox.style.display = 'block';
        }
      } finally {
        if (confirmBtn) {
          confirmBtn.disabled = false;
          confirmBtn.innerHTML = I18N[currentLang].delete_modal_confirm || '🗑️ Unwiderruflich löschen';
        }
      }
    }

    function openDecryptForCode(code) {
      switchTab('decrypt');
      document.getElementById('dec-code').value = code;
      document.getElementById('dec-key-a').focus();
    }

    function openInheritForCode(code) {
      switchTab('inherit');
      document.getElementById('inh-code').value = code;
      document.getElementById('inh-key-a').focus();
    }

    function openStopInheritForCode(code) {
      switchTab('inherit');
      document.getElementById('inh-code').value = code;
      document.getElementById('inh-key-a').focus();
    }

    // Close modals on Escape key
    document.addEventListener('keydown', (e) => {
      if (e.key === 'Escape') {
        closeInfoModal();
        closeAuthModal();
        closeDeleteModal();
      }
    });

    function setLanguage(lang) {
      if (!I18N[lang]) lang = 'de';
      currentLang = lang;
      localStorage.setItem('sv_lang', lang);
      document.documentElement.setAttribute('lang', lang);

      // Update button indicators
      document.getElementById('lang-btn-de').classList.toggle('active', lang === 'de');
      document.getElementById('lang-btn-en').classList.toggle('active', lang === 'en');

      // Update data-i18n elements
      document.querySelectorAll('[data-i18n]').forEach(elem => {
        const key = elem.getAttribute('data-i18n');
        if (I18N[lang][key]) {
          elem.innerHTML = I18N[lang][key];
        }
      });

      // Update data-i18n-placeholder elements
      document.querySelectorAll('[data-i18n-placeholder]').forEach(elem => {
        const key = elem.getAttribute('data-i18n-placeholder');
        if (I18N[lang][key]) {
          elem.setAttribute('placeholder', I18N[lang][key]);
        }
      });

      if (currentUser && document.getElementById('tab-vaults').style.display === 'block') {
        loadUserVaults();
      }
    }

    function initLanguage() {
      const saved = localStorage.getItem('sv_lang') || 'de';
      setLanguage(saved);
    }

    // View Navigation (Home vs App)
    function navigateTo(viewName, tabName) {
      if (viewName === 'app') {
        document.getElementById('view-home').style.display = 'none';
        document.getElementById('view-app').style.display = 'block';
        window.location.hash = 'vault';
        if (tabName) switchTab(tabName);
      } else {
        document.getElementById('view-home').style.display = 'block';
        document.getElementById('view-app').style.display = 'none';
        window.location.hash = '';
      }
    }

    function sendHeartbeat() {
      const token = localStorage.getItem('sv_auth_token');
      const headers = { 'Content-Type': 'application/json' };
      if (token) headers['Authorization'] = 'Bearer ' + token;
      fetch('/api/heartbeat', {
        method: 'POST',
        headers: headers,
        body: JSON.stringify({})
      }).catch(() => {});
    }

    // Auto-check URL hash or path on load & send activity heartbeat
    window.addEventListener('DOMContentLoaded', () => {
      initLanguage();
      checkAuthStatus().then(() => {
        sendHeartbeat();
        const hash = window.location.hash;
        const path = window.location.pathname;
        if (hash === '#app' || hash === '#vault' || path === '/app' || path === '/vault') {
          navigateTo('app');
        } else {
          navigateTo('home');
        }
      });
    });

    // Theme Management (Light mode default)
    function initTheme() {
      const saved = localStorage.getItem('sv_theme') || 'light';
      document.documentElement.setAttribute('data-theme', saved);
      updateThemeIcon(saved);
    }

    function toggleTheme() {
      const current = document.documentElement.getAttribute('data-theme') || 'light';
      const next = current === 'light' ? 'dark' : 'light';
      document.documentElement.setAttribute('data-theme', next);
      localStorage.setItem('sv_theme', next);
      updateThemeIcon(next);
    }

    function updateThemeIcon(theme) {
      const icon = document.getElementById('theme-icon');
      if (theme === 'dark') {
        icon.innerHTML = '<circle cx="12" cy="12" r="5"></circle><line x1="12" y1="1" x2="12" y2="3"></line><line x1="12" y1="21" x2="12" y2="23"></line><line x1="4.22" y1="4.22" x2="5.64" y2="5.64"></line><line x1="18.36" y1="18.36" x2="19.78" y2="19.78"></line><line x1="1" y1="12" x2="3" y2="12"></line><line x1="21" y1="12" x2="23" y2="12"></line><line x1="4.22" y1="19.78" x2="5.64" y2="18.36"></line><line x1="18.36" y1="5.64" x2="19.78" y2="4.22"></line>';
      } else {
        icon.innerHTML = '<path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z"></path>';
      }
    }

    initTheme();

    function formatFileSize(bytes) {
      if (bytes < 1024) return bytes + ' B';
      if (bytes < 1048576) return (bytes / 1024).toFixed(1) + ' KB';
      return (bytes / 1048576).toFixed(2) + ' MB';
    }

    function handleFileSelected(event) {
      const file = event.target.files[0];
      if (!file) return;

      const reader = new FileReader();
      reader.onload = function(e) {
        const base64Data = e.target.result.split(',')[1];
        selectedFileObject = {
          name: file.name,
          type: file.type || 'application/octet-stream',
          size: file.size,
          data: base64Data
        };
        document.getElementById('attached-file-name').textContent = file.name;
        document.getElementById('attached-file-size').textContent = formatFileSize(file.size);
        document.getElementById('attached-file-pill').style.display = 'flex';
        document.getElementById('file-dropzone').style.display = 'none';
      };
      reader.readAsDataURL(file);
    }

    function removeAttachedFile() {
      selectedFileObject = null;
      document.getElementById('file-input').value = '';
      document.getElementById('attached-file-pill').style.display = 'none';
      document.getElementById('file-dropzone').style.display = 'flex';
    }

    // Drag and drop support
    const dropzone = document.getElementById('file-dropzone');
    if (dropzone) {
      dropzone.addEventListener('dragover', (e) => { e.preventDefault(); dropzone.style.borderColor = 'var(--border-focus)'; });
      dropzone.addEventListener('dragleave', (e) => { e.preventDefault(); dropzone.style.borderColor = 'var(--border-subtle)'; });
      dropzone.addEventListener('drop', (e) => {
        e.preventDefault();
        dropzone.style.borderColor = 'var(--border-subtle)';
        if (e.dataTransfer.files.length) {
          document.getElementById('file-input').files = e.dataTransfer.files;
          handleFileSelected({ target: { files: e.dataTransfer.files } });
        }
      });
    }

    function switchTab(tabName) {
      document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
      const targetBtn = document.getElementById('tab-btn-' + tabName);
      if (targetBtn) targetBtn.classList.add('active');
      document.getElementById('tab-encrypt').style.display = tabName === 'encrypt' ? 'block' : 'none';
      document.getElementById('tab-decrypt').style.display = tabName === 'decrypt' ? 'block' : 'none';
      document.getElementById('tab-inherit').style.display = tabName === 'inherit' ? 'block' : 'none';
      document.getElementById('tab-vaults').style.display = tabName === 'vaults' ? 'block' : 'none';

      if (tabName === 'vaults' && currentUser) {
        loadUserVaults();
      }
    }

    async function handleEncrypt() {
      if (!currentUser) {
        openAuthModal('login');
        return;
      }

      const text = document.getElementById('plaintext').value.trim();
      const recipient_email = document.getElementById('recipient-email').value.trim();
      const errBox = document.getElementById('enc-error');
      const resBox = document.getElementById('enc-results');
      errBox.style.display = 'none';
      resBox.style.display = 'none';

      if (!text && !selectedFileObject) {
        errBox.textContent = I18N[currentLang].err_fill_payload;
        errBox.style.display = 'block';
        return;
      }

      if (!recipient_email || !recipient_email.includes('@') || !recipient_email.includes('.')) {
        errBox.textContent = I18N[currentLang].err_email_req;
        errBox.style.display = 'block';
        document.getElementById('recipient-email').focus();
        return;
      }

      try {
        const payload = { text, recipient_email };
        if (selectedFileObject) payload.file = selectedFileObject;

        const token = localStorage.getItem('sv_auth_token');
        const headers = { 'Content-Type': 'application/json' };
        if (token) headers['Authorization'] = 'Bearer ' + token;

        const res = await fetch('/api/encrypt', {
          method: 'POST',
          headers: headers,
          body: JSON.stringify(payload)
        });
        const data = await res.json();
        if (!res.ok) throw new Error(data.error || 'Encryption failed.');

        document.getElementById('res-code').textContent = data.code;
        document.getElementById('res-key-a').textContent = data.key_a;

        const emailInfo = document.getElementById('res-email-info');
        const msg = currentLang === 'de'
          ? `✉️ Empfänger registriert: <strong>${recipient_email}</strong> (Schlüssel B wird bei 30 Tagen Inaktivität gesendet; Datenlöschung 30 Tage danach).`
          : `✉️ Recipient registered: <strong>${recipient_email}</strong> (Key B dispatched after 30 days inactivity; data purged 30 days thereafter).`;
        emailInfo.innerHTML = msg;
        emailInfo.style.display = 'block';

        resBox.style.display = 'block';
      } catch (err) {
        errBox.textContent = err.message;
        errBox.style.display = 'block';
      }
    }

    async function handleDecrypt() {
      const code = document.getElementById('dec-code').value.trim();
      const key_a = document.getElementById('dec-key-a').value.trim();
      const key_b = document.getElementById('dec-key-b').value.trim();
      const errBox = document.getElementById('dec-error');
      const resBox = document.getElementById('dec-results');
      errBox.style.display = 'none';
      resBox.style.display = 'none';

      if (!code || !key_a) {
        errBox.textContent = I18N[currentLang].err_code_key_req;
        errBox.style.display = 'block';
        return;
      }

      try {
        const payload = { code, key_a };
        if (key_b) payload.key_b = key_b;

        const token = localStorage.getItem('sv_auth_token');
        const headers = { 'Content-Type': 'application/json' };
        if (token) headers['Authorization'] = 'Bearer ' + token;

        const res = await fetch('/api/decrypt', {
          method: 'POST',
          headers: headers,
          body: JSON.stringify(payload)
        });

        const data = await res.json();
        if (!res.ok) throw new Error(data.error || 'Decryption failed.');

        // 1. Text display
        const textSection = document.getElementById('dec-text-section');
        if (data.decrypted_text) {
          document.getElementById('res-decrypted').textContent = data.decrypted_text;
          textSection.style.display = 'block';
        } else {
          textSection.style.display = 'none';
        }

        // 2. File display
        const fileSection = document.getElementById('dec-file-section');
        if (data.file && data.file.data) {
          decryptedFileObject = data.file;
          document.getElementById('dec-file-name').textContent = data.file.name || 'encrypted_file';
          document.getElementById('dec-file-size').textContent = formatFileSize(data.file.size || 0);
          fileSection.style.display = 'flex';
        } else {
          decryptedFileObject = null;
          fileSection.style.display = 'none';
        }

        currentDecryptedCode = code;
        currentDecryptedKeyA = key_a;
        const actionsSection = document.getElementById('dec-actions-section');
        if (actionsSection) actionsSection.style.display = 'flex';

        resBox.style.display = 'block';
      } catch (err) {
        errBox.textContent = err.message;
        errBox.style.display = 'block';
      }
    }

    function downloadDecryptedFile() {
      if (!decryptedFileObject || !decryptedFileObject.data) return;

      const byteCharacters = atob(decryptedFileObject.data);
      const byteNumbers = new Array(byteCharacters.length);
      for (let i = 0; i < byteCharacters.length; i++) {
        byteNumbers[i] = byteCharacters.charCodeAt(i);
      }
      const byteArray = new Uint8Array(byteNumbers);
      const blob = new Blob([byteArray], { type: decryptedFileObject.type || 'application/octet-stream' });
      const url = URL.createObjectURL(blob);

      const a = document.createElement('a');
      a.href = url;
      a.download = decryptedFileObject.name || 'downloaded_file';
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
    }

    async function handleInherit() {
      const code = document.getElementById('inh-code').value.trim();
      const key_a = document.getElementById('inh-key-a').value.trim();
      const errBox = document.getElementById('inh-error');
      const resBox = document.getElementById('inh-results');
      errBox.style.display = 'none';
      resBox.style.display = 'none';

      if (!code || !key_a) {
        errBox.textContent = I18N[currentLang].err_code_key_req;
        errBox.style.display = 'block';
        return;
      }

      try {
        const token = localStorage.getItem('sv_auth_token');
        const headers = { 'Content-Type': 'application/json' };
        if (token) headers['Authorization'] = 'Bearer ' + token;

        const res = await fetch('/api/inherit', {
          method: 'POST',
          headers: headers,
          body: JSON.stringify({ code, key_a })
        });

        const data = await res.json();
        if (!res.ok) throw new Error(data.error || 'Handover failed.');

        const alertStatus = document.getElementById('inh-alert-status');
        const keyField = document.getElementById('inh-key-field');

        if (data.recipient_email) {
          keyField.style.display = 'none';
          alertStatus.innerHTML = `🚀 ${I18N[currentLang].inh_success}`;
          alertStatus.style.display = 'block';
        } else if (data.key_b) {
          document.getElementById('res-key-b').textContent = data.key_b;
          keyField.style.display = 'block';
          alertStatus.innerHTML = `🚀 <strong>${currentLang === 'de' ? 'Nachlass übergeben' : 'Custody Handover Executed'}:</strong> ${currentLang === 'de' ? 'Schlüssel B wurde freigegeben und vom Server gelöscht.' : 'Key B has been released and purged from server.'}`;
          alertStatus.style.display = 'block';
        } else {
          keyField.style.display = 'none';
          alertStatus.innerHTML = `🚀 ${I18N[currentLang].inh_success}`;
          alertStatus.style.display = 'block';
        }

        resBox.style.display = 'block';
      } catch (err) {
        errBox.textContent = err.message;
        errBox.style.display = 'block';
      }
    }

    async function handleStopInheritance() {
      const code = document.getElementById('inh-code').value.trim();
      const key_a = document.getElementById('inh-key-a').value.trim();
      const errBox = document.getElementById('inh-error');
      const resBox = document.getElementById('inh-results');
      errBox.style.display = 'none';
      resBox.style.display = 'none';

      if (!code || !key_a) {
        errBox.textContent = I18N[currentLang].err_code_key_req;
        errBox.style.display = 'block';
        return;
      }

      try {
        const token = localStorage.getItem('sv_auth_token');
        const headers = { 'Content-Type': 'application/json' };
        if (token) headers['Authorization'] = 'Bearer ' + token;

        const res = await fetch('/api/disable-inheritance', {
          method: 'POST',
          headers: headers,
          body: JSON.stringify({ code, key_a })
        });

        const data = await res.json();
        if (!res.ok) throw new Error(data.error || 'Failed to disable auto-inheritance.');

        const alertStatus = document.getElementById('inh-alert-status');
        const keyField = document.getElementById('inh-key-field');
        keyField.style.display = 'none';
        alertStatus.innerHTML = `🛑 ${I18N[currentLang].inh_stopped_success}`;
        alertStatus.style.display = 'block';
        resBox.style.display = 'block';
      } catch (err) {
        errBox.textContent = err.message;
        errBox.style.display = 'block';
      }
    }

    function copyText(elemId, btn) {
      const elem = document.getElementById(elemId);
      if (!elem) return;
      const text = elem.textContent.trim();
      if (!text) return;

      const orig = btn.textContent;
      btn.textContent = I18N[currentLang].btn_copied || 'Kopiert';
      btn.style.color = 'var(--success)';
      setTimeout(() => {
        btn.textContent = orig;
        btn.style.color = '';
      }, 1500);

      if (navigator.clipboard && window.isSecureContext) {
        navigator.clipboard.writeText(text).catch(() => { fallbackCopy(text); });
      } else {
        fallbackCopy(text);
      }
    }

    function fallbackCopy(text) {
      const textArea = document.createElement('textarea');
      textArea.value = text;
      textArea.style.position = 'fixed';
      textArea.style.left = '-999999px';
      document.body.appendChild(textArea);
      textArea.focus();
      textArea.select();
      try { document.execCommand('copy'); } catch (e) {}
      document.body.removeChild(textArea);
    }
  </script>
</body>
</html>
"""


def process_inactive_vault_records(
    storage_dir: str = storage.DEFAULT_STORAGE_DIR,
    inactivity_days: int = DEFAULT_INACTIVITY_DAYS,
    base_url: str = "http://localhost:8080",
) -> int:
    """
    Check for records that have had no user activity for `inactivity_days`
    and automatically switch them to Inherited Mode (sending Key B to recipient).
    Also purges records that have been in Inherited Mode for 30+ days.
    """
    # 1. Switch inactive normal records to Inherited Mode
    expired_codes = storage.get_inactive_expired_records(inactivity_days, storage_dir)
    for code in expired_codes:
        try:
            key_b, encrypted_text, recipient_email = storage.switch_to_inherited_mode(code, storage_dir)
            sys.stderr.write(
                f"[Auto-Inheritance] Record '{code}' exceeded {inactivity_days} days of inactivity. Switched to Inherited Mode.\n"
            )
            if recipient_email:
                email_service.send_key_b_email(
                    to_email=recipient_email,
                    code=code,
                    key_b=key_b,
                    server_url=base_url,
                )
                sys.stderr.write(f"[Auto-Inheritance] Dispatched Key B to recipient <{recipient_email}> for record '{code}'.\n")
        except Exception as e:
            sys.stderr.write(f"[Auto-Inheritance Error] Failed processing inactive code '{code}': {e}\n")

    # 2. Purge records in Inherited Mode older than 30 days (Dead Man service policy)
    try:
        purged_codes = storage.purge_expired_inherited_records(purge_days=30, storage_dir=storage_dir)
        for pcode in purged_codes:
            sys.stderr.write(
                f"[Data-Purge] Record '{pcode}' exceeded 30-day inheritance window and was permanently deleted from disk.\n"
            )
    except Exception as e:
        sys.stderr.write(f"[Data-Purge Error] Failed during inherited data purge scan: {e}\n")

    sys.stderr.flush()
    return len(expired_codes)


def start_inactivity_monitor_thread(
    server, check_interval_seconds: int = 60
) -> threading.Thread:
    """Start background daemon thread to monitor and trigger automated inactivity inheritance."""
    def monitor_loop():
        while True:
            time.sleep(check_interval_seconds)
            try:
                host_str = server.server_address[0]
                if host_str == "0.0.0.0":
                    host_str = "localhost"
                port = server.server_address[1]
                proto = "https" if getattr(server, "is_ssl", False) else "http"
                base_url = f"{proto}://{host_str}:{port}"

                process_inactive_vault_records(
                    storage_dir=server.storage_dir,
                    inactivity_days=getattr(server, "inactivity_days", DEFAULT_INACTIVITY_DAYS),
                    base_url=base_url,
                )
            except Exception as e:
                sys.stderr.write(f"[Inactivity Monitor Error] {e}\n")

    thread = threading.Thread(target=monitor_loop, daemon=True)
    thread.start()
    return thread


def ensure_self_signed_cert(cert_path: str = "cert.pem", key_path: str = "key.pem") -> Tuple[str, str]:
    """Generate self-signed SSL/TLS certificate if not existing."""
    if os.path.isfile(cert_path) and os.path.isfile(key_path):
        return cert_path, key_path

    try:
        from cryptography import x509
        from cryptography.hazmat.backends import default_backend
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.x509.oid import NameOID

        key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "CH"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "SecureVault Switzerland"),
            x509.NameAttribute(NameOID.COMMON_NAME, "localhost"),
        ])
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.datetime.now(datetime.timezone.utc))
            .not_valid_after(datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=3650))
            .sign(key, hashes.SHA256(), default_backend())
        )

        from cryptography.hazmat.primitives import serialization
        with open(key_path, "wb") as f:
            f.write(key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption(),
            ))
        with open(cert_path, "wb") as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))

        return cert_path, key_path
    except Exception as e:
        sys.stderr.write(f"[SSL Warning] Could not auto-generate SSL certificate: {e}\n")
        return cert_path, key_path


def get_authenticated_user(handler: BaseHTTPRequestHandler) -> Optional[str]:
    """Extract authenticated username from Authorization header, X-Auth-Token, or cookie with file-backed persistence."""
    sessions_dir = getattr(handler.server, "sessions_dir", storage.DEFAULT_SESSIONS_DIR)

    auth_header = handler.headers.get("Authorization", "")
    if auth_header.startswith("Bearer "):
        token = auth_header[7:].strip()
        user = storage.get_session_username(token, sessions_dir)
        if user:
            return user

    x_token = handler.headers.get("X-Auth-Token", "").strip()
    if x_token:
        user = storage.get_session_username(x_token, sessions_dir)
        if user:
            return user

    cookie_header = handler.headers.get("Cookie", "")
    if cookie_header:
        for part in cookie_header.split(";"):
            if "=" in part:
                k, v = part.strip().split("=", 1)
                if k == "sv_session":
                    token = v.strip()
                    user = storage.get_session_username(token, sessions_dir)
                    if user:
                        return user

    return None


class CodeGenRequestHandler(BaseHTTPRequestHandler):
    """HTTP Request Handler for 256-Bit Split Vault Server."""

    server_version = f"SecureVault/{SERVER_VERSION}"

    def do_OPTIONS(self) -> None:
        """Handle CORS pre-flight requests."""
        self.send_response(HTTPStatus.NO_CONTENT)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Accept, X-Device-ID, Authorization, X-Auth-Token")
        self.end_headers()

    def do_GET(self) -> None:
        """Handle incoming GET requests."""
        parsed_url = urlparse(self.path)
        path = parsed_url.path.rstrip("/")
        query_params = parse_qs(parsed_url.query)

        # Route: Root Web UI & App Subpages
        if path in ("", "/app", "/vault", "/ui", "/web"):
            user_agent = self.headers.get("User-Agent", "").lower()
            if "curl" in user_agent or "wget" in user_agent or "httpie" in user_agent:
                self.handle_code(query_params)
                return

            self.send_html_response(HTML_TEMPLATE)
            return

        # Route: Current authenticated user session status
        if path == "/api/me":
            current_user = get_authenticated_user(self)
            if current_user:
                self.send_json_response(HTTPStatus.OK, {
                    "authenticated": True,
                    "username": current_user,
                })
            else:
                self.send_json_response(HTTPStatus.OK, {
                    "authenticated": False,
                    "username": None,
                })
            return

        # Route: List all vaults owned by the logged-in user
        if path == "/api/my-vaults":
            current_user = get_authenticated_user(self)
            if not current_user:
                self.send_error_response(HTTPStatus.UNAUTHORIZED, "Authentication required. Please log in to view your vaults.")
                return

            storage.touch_user_vaults(current_user, self.server.storage_dir)
            vaults = storage.get_user_vaults(
                username=current_user,
                inactivity_days=int(self.server.inactivity_days),
                storage_dir=self.server.storage_dir,
            )
            self.send_json_response(HTTPStatus.OK, {
                "status": "success",
                "username": current_user,
                "vaults": vaults,
                "count": len(vaults),
            })
            return

        # Route: Random Code generation
        if path in ("/code", "/api/code"):
            self.handle_code(query_params)
            return

        # Route: Healthcheck
        if path == "/health":
            self.handle_health()
            return

        # 404 Not Found
        self.send_error_response(
            HTTPStatus.NOT_FOUND,
            f"Endpoint '{self.path}' not found. Available endpoints: /, /app, /api/me, /api/my-vaults, /api/register, /api/login, /api/logout, /api/encrypt, /api/decrypt, /api/inherit, /api/heartbeat, /health",
        )

    def do_POST(self) -> None:
        """Handle incoming POST requests."""
        parsed_url = urlparse(self.path)
        path = parsed_url.path.rstrip("/")

        content_length = int(self.headers.get("Content-Length", 0))
        data = {}
        if content_length > 0:
            try:
                body = self.rfile.read(content_length).decode("utf-8")
                data = json.loads(body)
            except Exception as e:
                self.send_error_response(HTTPStatus.BAD_REQUEST, f"Invalid JSON payload: {e}")
                return

        # Route: Register new user account
        if path == "/api/register":
            username = (data.get("username") or "").strip()
            password = data.get("password") or ""
            if not username or not password:
                self.send_error_response(HTTPStatus.BAD_REQUEST, "Username and password are required.")
                return

            try:
                user_info = storage.save_user(username, password, self.server.users_dir)
                token = secrets.token_hex(32)
                storage.save_session(token, user_info["username"], duration_days=30, sessions_dir=self.server.sessions_dir)
                cookie = f"sv_session={token}; Path=/; HttpOnly; SameSite=Lax; Max-Age=2592000"
                self.send_json_response(HTTPStatus.OK, {
                    "status": "success",
                    "username": user_info["username"],
                    "token": token,
                    "message": f"Account '{user_info['username']}' registered successfully."
                }, cookies=[cookie])
            except Exception as e:
                self.send_error_response(HTTPStatus.BAD_REQUEST, str(e))
            return

        # Route: Login existing user account
        if path == "/api/login":
            username = (data.get("username") or "").strip()
            password = data.get("password") or ""
            if not username or not password:
                self.send_error_response(HTTPStatus.BAD_REQUEST, "Username and password are required.")
                return

            valid = storage.verify_user_password(username, password, self.server.users_dir)
            if not valid:
                self.send_error_response(HTTPStatus.UNAUTHORIZED, "Invalid username or password.")
                return

            u_rec = storage.get_user(username, self.server.users_dir)
            display_user = u_rec.get("username") if u_rec else username
            token = secrets.token_hex(32)
            storage.save_session(token, display_user, duration_days=30, sessions_dir=self.server.sessions_dir)
            cookie = f"sv_session={token}; Path=/; HttpOnly; SameSite=Lax; Max-Age=2592000"
            self.send_json_response(HTTPStatus.OK, {
                "status": "success",
                "username": display_user,
                "token": token,
                "message": f"Logged in as {display_user}."
            }, cookies=[cookie])
            return

        # Route: Logout user session
        if path == "/api/logout":
            sessions_dir = self.server.sessions_dir
            auth_header = self.headers.get("Authorization", "")
            if auth_header.startswith("Bearer "):
                storage.delete_session(auth_header[7:].strip(), sessions_dir)
            cookie_header = self.headers.get("Cookie", "")
            if cookie_header:
                for part in cookie_header.split(";"):
                    if "=" in part:
                        k, v = part.strip().split("=", 1)
                        if k == "sv_session":
                            storage.delete_session(v.strip(), sessions_dir)
            cookie = "sv_session=; Path=/; HttpOnly; Max-Age=0"
            self.send_json_response(HTTPStatus.OK, {"status": "success", "message": "Logged out successfully."}, cookies=[cookie])
            return

        # Route: Heartbeat / Activity ping (updates last_active_at)
        if path in ("/api/heartbeat", "/api/touch"):
            current_user = get_authenticated_user(self)
            updated = 0
            if current_user:
                updated += storage.touch_user_vaults(current_user, self.server.storage_dir)
            code = data.get("code")
            if code:
                storage.touch_record_activity(str(code), self.server.storage_dir)
                updated += 1
            self.send_json_response(HTTPStatus.OK, {"status": "ok", "updated_records": updated})
            return

        # Route: SMTP Test Diagnostics
        if path == "/api/test-email":
            to_addr = data.get("to") or data.get("email")
            success, msg = email_service.test_smtp_connection(to_addr)
            status_code = HTTPStatus.OK if success else HTTPStatus.BAD_REQUEST
            self.send_json_response(status_code, {
                "success": success,
                "message": msg,
                "smtp_configured": email_service.is_smtp_configured(),
            })
            return

        # Route: Encrypt (256-Bit Split AES-GCM with Text and/or File) - Requires Account Login
        if path == "/api/encrypt":
            current_user = get_authenticated_user(self)
            if not current_user:
                self.send_error_response(
                    HTTPStatus.UNAUTHORIZED,
                    "Authentication required. Please log in or register to encrypt and store data."
                )
                return

            plaintext = data.get("text", "")
            file_obj = data.get("file")
            recipient_email = (data.get("recipient_email") or "").strip()
            device_id = data.get("device_id") or self.headers.get("X-Device-ID")
            raw_inactivity = data.get("inactivity_days")
            inactivity_days = int(raw_inactivity) if raw_inactivity is not None else int(self.server.inactivity_days)
            auto_inherit = True

            if not plaintext and not file_obj:
                self.send_error_response(HTTPStatus.BAD_REQUEST, "Must provide 'text' or 'file' in JSON payload.")
                return

            if not recipient_email or "@" not in recipient_email or "." not in recipient_email.split("@")[-1]:
                self.send_error_response(
                    HTTPStatus.BAD_REQUEST,
                    "Recipient email is strictly required. An email address is mandatory for the 30-day inactivity emergency handover."
                )
                return

            # Package text and file into unified payload before encryption
            package = {
                "text": plaintext or "",
                "file": file_obj if isinstance(file_obj, dict) else None,
            }
            package_json = json.dumps(package)

            try:
                key_bits = self.server.key_bits
                crypto_result = encrypt_split(plaintext=package_json, key_bits=key_bits)
                key_a = crypto_result["key_a"]
                key_b = crypto_result["key_b"]
                encrypted_text = crypto_result["encrypted_text"]

                storage_dir = self.server.storage_dir
                while True:
                    code = generate_code(length=16, charset="alphanumeric")
                    if not storage.code_exists(code, storage_dir):
                        break

                storage.save_vault_record(
                    code=code,
                    encrypted_text=encrypted_text,
                    server_key_b=key_b,
                    recipient_email=recipient_email,
                    owner_username=current_user,
                    device_id=device_id,
                    mode="normal",
                    inactivity_days=inactivity_days,
                    auto_inherit=auto_inherit,
                    storage_dir=storage_dir,
                )

                self.send_json_response(
                    HTTPStatus.OK,
                    {
                        "code": code,
                        "key_a": key_a,
                        "key_bits": key_bits,
                        "has_file": bool(file_obj),
                        "owner_username": current_user,
                        "recipient_email": recipient_email.strip() if recipient_email else None,
                        "inactivity_days": inactivity_days,
                        "auto_inherit": auto_inherit,
                        "mode": "normal",
                        "algorithm": f"AES-256-GCM ({key_bits}-Bit Split)",
                        "message": f"Encrypted payload saved under code '{code}' bound to account '{current_user}'.",
                        "created_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                    },
                )
            except Exception as e:
                self.send_error_response(HTTPStatus.BAD_REQUEST, str(e))
            return

        # Route: Disable / Stop Auto-Inheritance for a specific code
        if path == "/api/disable-inheritance":
            code = data.get("code")
            key_a = data.get("key_a") or data.get("key")
            current_user = get_authenticated_user(self)

            if not code or not key_a:
                self.send_error_response(HTTPStatus.BAD_REQUEST, "Both 'code' and 'key_a' are required to stop auto-inheritance.")
                return

            clean_code = str(code).strip()
            storage_dir = self.server.storage_dir
            record = storage.load_vault_record(clean_code, storage_dir)

            if record is None:
                self.send_error_response(HTTPStatus.NOT_FOUND, f"No record found for code '{clean_code}'.")
                return

            if record.get("mode") == "inherited":
                self.send_error_response(HTTPStatus.BAD_REQUEST, f"Record '{clean_code}' has already been transferred to Inherited Mode.")
                return

            owner = record.get("owner_username")
            if owner and current_user and current_user.lower() != owner.lower():
                self.send_error_response(HTTPStatus.FORBIDDEN, "You are not authorized to modify this vault.")
                return

            server_key_b = record.get("server_key_b")
            if not server_key_b:
                self.send_error_response(HTTPStatus.BAD_REQUEST, "Vault has no valid server key.")
                return

            # Cryptographically verify Key A
            try:
                decrypt_split(
                    record["encrypted_text"],
                    str(key_a).strip(),
                    server_key_b.strip(),
                )
            except Exception:
                self.send_error_response(HTTPStatus.UNAUTHORIZED, "Invalid Key A for this storage code.")
                return

            storage.disable_auto_inheritance(clean_code, storage_dir)
            self.send_json_response(HTTPStatus.OK, {
                "status": "success",
                "code": clean_code,
                "auto_inherit": False,
                "inactivity_days": 0,
                "message": f"Auto-inheritance has been permanently stopped for record '{clean_code}'."
            })
            return

        # Route: Transfer / Switch to Inherited Mode (Manual Handover)
        if path == "/api/inherit":
            code = data.get("code")
            key_a = data.get("key_a") or data.get("key")
            current_user = get_authenticated_user(self)

            if not code or not key_a:
                self.send_error_response(HTTPStatus.BAD_REQUEST, "Both 'code' and 'key_a' are required for manual handover.")
                return

            clean_code = str(code).strip()
            storage_dir = self.server.storage_dir
            record = storage.load_vault_record(clean_code, storage_dir)

            if record is None:
                self.send_error_response(HTTPStatus.NOT_FOUND, f"No record found for code '{clean_code}'.")
                return

            owner = record.get("owner_username")
            if owner and current_user and current_user.lower() != owner.lower():
                self.send_error_response(HTTPStatus.FORBIDDEN, "You are not authorized to trigger handover for this vault.")
                return

            server_key_b = record.get("server_key_b")
            if not server_key_b:
                self.send_error_response(HTTPStatus.BAD_REQUEST, "Vault has already been transferred or has no server key.")
                return

            # Cryptographically verify Key A
            try:
                decrypt_split(record["encrypted_text"], str(key_a).strip(), server_key_b.strip())
            except Exception:
                self.send_error_response(HTTPStatus.UNAUTHORIZED, "Invalid Key A for this storage code.")
                return

            try:
                key_b, encrypted_text, recipient_email = storage.switch_to_inherited_mode(clean_code, storage_dir)

                email_sent = False
                email_status = "No recipient email was configured for this record."
                if recipient_email:
                    host_header = self.headers.get("Host", f"localhost:{self.server.server_address[1]}")
                    proto = "https" if isinstance(self.request, ssl.SSLSocket) else "http"
                    server_url = f"{proto}://{host_header}"
                    email_sent, email_status = email_service.send_key_b_email(
                        to_email=recipient_email,
                        code=clean_code,
                        key_b=key_b,
                        server_url=server_url,
                    )

                resp_payload = {
                    "code": clean_code,
                    "recipient_email": recipient_email,
                    "email_sent": email_sent,
                    "email_status": email_status,
                    "mode": "inherited",
                    "status": "success",
                }
                if not recipient_email:
                    resp_payload["key_b"] = key_b
                    resp_payload["message"] = f"Key B released to user and deleted from backend for record '{clean_code}'."
                else:
                    resp_payload["message"] = f"Key B dispatched to {recipient_email} and deleted from backend for record '{clean_code}'. Key B is omitted from response for privacy."

                self.send_json_response(HTTPStatus.OK, resp_payload)
            except Exception as e:
                self.send_error_response(HTTPStatus.BAD_REQUEST, str(e))
            return

        # Route: Decrypt by Code + Key A (+ Key B if in Inherited Mode or not logged in as owner)
        if path == "/api/decrypt":
            code = data.get("code")
            key_a = data.get("key_a") or data.get("key")
            key_b = data.get("key_b")
            current_user = get_authenticated_user(self)

            if not code or not key_a:
                self.send_error_response(
                    HTTPStatus.BAD_REQUEST,
                    "Both 'code' (16-character code) and 'key_a' must be provided.",
                )
                return

            clean_code = str(code).strip()
            storage_dir = self.server.storage_dir
            record = storage.load_vault_record(clean_code, storage_dir)

            if record is None:
                self.send_error_response(
                    HTTPStatus.NOT_FOUND,
                    f"No encrypted vault record found for code '{clean_code}'.",
                )
                return

            mode = record.get("mode", "normal")
            encrypted_text = record.get("encrypted_text", "")
            server_key_b = record.get("server_key_b")
            owner = record.get("owner_username")
            is_owner = bool(current_user and owner and current_user.lower() == owner.lower())

            if mode == "inherited":
                if not key_b:
                    self.send_error_response(
                        HTTPStatus.BAD_REQUEST,
                        "Record is in Inherited Mode. Both Key A and Key B must be provided to decrypt.",
                    )
                    return
                effective_key_b = key_b
            else:
                # Normal Mode:
                if key_b:
                    effective_key_b = key_b
                elif server_key_b and is_owner:
                    effective_key_b = server_key_b
                    # Touch activity timestamp on successful decryption by owner
                    storage.touch_record_activity(clean_code, storage_dir)
                    if current_user:
                        storage.touch_user_vaults(current_user, storage_dir)
                elif server_key_b and not owner:
                    # Legacy record without owner
                    effective_key_b = server_key_b
                    storage.touch_record_activity(clean_code, storage_dir)
                else:
                    self.send_error_response(
                        HTTPStatus.BAD_REQUEST,
                        "Key B is required to decrypt unless you are logged into the account that created this vault.",
                    )
                    return

            try:
                decrypted_raw = decrypt_split(
                    encrypted_b64=encrypted_text,
                    key_a_b64=key_a,
                    key_b_b64=effective_key_b,
                )

                # Parse unified container (handles text + file, plus backwards compatibility)
                decrypted_text = ""
                decrypted_file = None
                try:
                    container = json.loads(decrypted_raw)
                    if isinstance(container, dict) and ("text" in container or "file" in container):
                        decrypted_text = container.get("text", "")
                        decrypted_file = container.get("file")
                    else:
                        decrypted_text = decrypted_raw
                except Exception:
                    decrypted_text = decrypted_raw

                self.send_json_response(
                    HTTPStatus.OK,
                    {
                        "code": clean_code,
                        "decrypted_text": decrypted_text,
                        "file": decrypted_file,
                        "mode": mode,
                        "status": "success",
                    },
                )
            except Exception as e:
                self.send_error_response(HTTPStatus.BAD_REQUEST, str(e))
            return

        # Route: Delete a vault and attached file permanently from server
        if path in ("/api/delete-vault", "/api/delete"):
            code = data.get("code")
            key_a = data.get("key_a") or data.get("key")
            current_user = get_authenticated_user(self)

            if not code:
                self.send_error_response(HTTPStatus.BAD_REQUEST, "Missing 'code' parameter in request.")
                return

            clean_code = str(code).strip()
            storage_dir = self.server.storage_dir
            record = storage.load_vault_record(clean_code, storage_dir)

            if record is None:
                self.send_error_response(HTTPStatus.NOT_FOUND, f"No vault record found for code '{clean_code}'.")
                return

            owner = record.get("owner_username")
            authorized = False

            # 1. Check if logged-in user is the owner
            if owner and current_user and current_user.lower() == owner.lower():
                authorized = True
            # 2. Check if valid Key A provided
            elif key_a:
                server_key_b = record.get("server_key_b")
                if server_key_b:
                    try:
                        decrypt_split(record["encrypted_text"], str(key_a).strip(), server_key_b.strip())
                        authorized = True
                    except Exception:
                        pass
                else:
                    authorized = True
            # 3. If record has no owner and not authenticated
            elif not owner:
                authorized = True

            if not authorized:
                self.send_error_response(
                    HTTPStatus.UNAUTHORIZED,
                    "Unauthorized. You must either be logged in as the owner of this vault or provide a valid Key A."
                )
                return

            deleted = storage.delete_vault_record(clean_code, storage_dir)
            if deleted:
                self.send_json_response(HTTPStatus.OK, {
                    "status": "success",
                    "code": clean_code,
                    "message": f"Vault record '{clean_code}' and all attached files were permanently deleted from the server."
                })
            else:
                self.send_error_response(HTTPStatus.INTERNAL_SERVER_ERROR, f"Could not delete file for code '{clean_code}'.")
            return

        self.send_error_response(HTTPStatus.NOT_FOUND, f"Endpoint '{self.path}' not found.")

    def do_HEAD(self) -> None:
        """Handle incoming HEAD requests."""
        parsed_url = urlparse(self.path)
        path = parsed_url.path.rstrip("/")
        if path in ("", "/app", "/vault", "/code", "/api/code", "/health", "/ui"):
            self.send_response(HTTPStatus.OK)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
        else:
            self.send_response(HTTPStatus.NOT_FOUND)
            self.end_headers()

    def handle_health(self) -> None:
        """Respond with health status and uptime metrics."""
        uptime = round(time.time() - SERVER_START_TIME, 2)
        payload = {
            "status": "healthy",
            "jurisdiction": "Switzerland",
            "version": SERVER_VERSION,
            "uptime_seconds": uptime,
            "key_bits": self.server.key_bits,
            "inactivity_days": self.server.inactivity_days,
            "smtp_configured": email_service.is_smtp_configured(),
            "storage_dir": self.server.storage_dir,
            "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        }
        self.send_json_response(HTTPStatus.OK, payload)

    def handle_code(self, query_params: dict) -> None:
        """Generate and respond with a random code."""
        length = self.server.default_length
        if "length" in query_params:
            try:
                length = int(query_params["length"][0])
                if length <= 0 or length > MAX_LENGTH:
                    self.send_error_response(
                        HTTPStatus.BAD_REQUEST,
                        f"Query parameter 'length' must be between 1 and {MAX_LENGTH}.",
                    )
                    return
            except ValueError:
                self.send_error_response(
                    HTTPStatus.BAD_REQUEST,
                    "Query parameter 'length' must be a valid integer.",
                )
                return

        charset = query_params.get("charset", [self.server.default_charset])[0]

        req_format = query_params.get("format", [None])[0]
        if req_format is None:
            accept_header = self.headers.get("Accept", "")
            if "application/json" in accept_header:
                req_format = "json"
            else:
                req_format = self.server.default_format

        try:
            code = generate_code(length=length, charset=charset)
        except ValueError as err:
            self.send_error_response(HTTPStatus.BAD_REQUEST, str(err))
            return

        if req_format.lower() == "json":
            response_data = {
                "code": code,
                "length": len(code),
                "charset": charset,
                "created_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            }
            self.send_json_response(HTTPStatus.OK, response_data)
        else:
            self.send_text_response(HTTPStatus.OK, f"{code}\n")

    def send_html_response(self, html_content: str) -> None:
        """Send an HTML page response."""
        body = html_content.encode("utf-8")
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.end_headers()
        self.wfile.write(body)

    def send_json_response(self, status: HTTPStatus, data: dict, cookies: Optional[List[str]] = None) -> None:
        """Send a JSON formatted response with optional Set-Cookie headers."""
        body = json.dumps(data, indent=2).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("X-Content-Type-Options", "nosniff")
        if cookies:
            for c in cookies:
                self.send_header("Set-Cookie", c)
        self.end_headers()
        self.wfile.write(body)

    def send_text_response(self, status: HTTPStatus, text: str) -> None:
        """Send a plain text response."""
        body = text.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(body)

    def send_error_response(self, status: HTTPStatus, message: str) -> None:
        """Send a structured error message."""
        accept_header = self.headers.get("Accept", "")
        if "application/json" in accept_header or self.path.startswith("/api/"):
            self.send_json_response(status, {"error": message, "code": status.value})
        else:
            self.send_text_response(status, f"Error {status.value}: {message}\n")

    def log_message(self, format: str, *args) -> None:
        """Custom formatted log message."""
        sys.stderr.write(
            f"[{self.log_date_time_string()}] {self.address_string()} - {format % args}\n"
        )


class CodeGenServer(ThreadingHTTPServer):
    """Custom ThreadingHTTPServer holding server configurations."""

    allow_reuse_address = True

    def __init__(
        self,
        server_address,
        RequestHandlerClass,
        default_length=DEFAULT_LENGTH,
        default_charset=DEFAULT_CHARSET,
        default_format="text",
        storage_dir=storage.DEFAULT_STORAGE_DIR,
        users_dir=None,
        sessions_dir=None,
        key_bits=DEFAULT_KEY_BITS,
        inactivity_days=DEFAULT_INACTIVITY_DAYS,
    ):
        super().__init__(server_address, RequestHandlerClass)
        self.default_length = default_length
        self.default_charset = default_charset
        self.default_format = default_format
        self.storage_dir = storage_dir
        if users_dir:
            self.users_dir = users_dir
        else:
            self.users_dir = os.getenv("USERS_DIR", os.path.join(self.storage_dir, "users"))
        if sessions_dir:
            self.sessions_dir = sessions_dir
        else:
            self.sessions_dir = os.getenv("SESSIONS_DIR", os.path.join(self.storage_dir, "sessions"))
        self.key_bits = key_bits
        self.inactivity_days = inactivity_days
        self.is_ssl = False
        storage.ensure_storage_dir(self.storage_dir)
        storage.ensure_users_dir(self.users_dir)
        storage.ensure_sessions_dir(self.sessions_dir)


def parse_arguments() -> argparse.Namespace:
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        description="SecureVault: 256-Bit Dual-Key Split Encryption Server (Switzerland)"
    )
    parser.add_argument(
        "-p",
        "--port",
        type=int,
        default=int(os.getenv("PORT", "8080")),
        help="Port to listen on (default: 8080, or env $PORT)",
    )
    parser.add_argument(
        "-H",
        "--host",
        type=str,
        default=os.getenv("HOST", "0.0.0.0"),
        help="Host address to bind to (default: 0.0.0.0, or env $HOST)",
    )
    parser.add_argument(
        "-s",
        "--storage-dir",
        type=str,
        default=storage.DEFAULT_STORAGE_DIR,
        help=f"Directory to store encrypted files (default: {storage.DEFAULT_STORAGE_DIR})",
    )
    parser.add_argument(
        "-k",
        "--key-bits",
        type=int,
        default=int(os.getenv("KEY_BITS", str(DEFAULT_KEY_BITS))),
        choices=[256, 1024, 2048, 4096],
        help=f"Key size in bits (default: {DEFAULT_KEY_BITS})",
    )
    parser.add_argument(
        "--inactivity-days",
        type=int,
        default=int(os.getenv("INACTIVITY_DAYS", str(DEFAULT_INACTIVITY_DAYS))),
        help=f"Days of inactivity before automatic inheritance trigger (default: {DEFAULT_INACTIVITY_DAYS})",
    )
    parser.add_argument(
        "--ssl",
        action="store_true",
        default=os.getenv("SSL_ENABLED", "false").lower() in ("true", "1", "yes"),
        help="Enable HTTPS / SSL encryption",
    )
    parser.add_argument(
        "--ssl-cert",
        type=str,
        default=os.getenv("SSL_CERT", "cert.pem"),
        help="Path to SSL certificate (default: cert.pem)",
    )
    parser.add_argument(
        "--ssl-key",
        type=str,
        default=os.getenv("SSL_KEY", "key.pem"),
        help="Path to SSL private key (default: key.pem)",
    )
    parser.add_argument(
        "-l",
        "--length",
        type=int,
        default=int(os.getenv("CODE_LENGTH", str(DEFAULT_LENGTH))),
        help=f"Default length of generated codes (default: {DEFAULT_LENGTH})",
    )
    parser.add_argument(
        "-c",
        "--charset",
        type=str,
        default=os.getenv("CHARSET", DEFAULT_CHARSET),
        choices=list(CHARSETS.keys()),
        help=f"Default character set (default: {DEFAULT_CHARSET})",
    )
    parser.add_argument(
        "-f",
        "--format",
        type=str,
        default=os.getenv("DEFAULT_FORMAT", "text"),
        choices=["text", "json"],
        help="Default response format for /code (text or json, default: text)",
    )
    parser.add_argument(
        "--monitor-port",
        type=int,
        default=int(os.getenv("MONITOR_PORT", str(monitor_server.DEFAULT_MONITOR_PORT))),
        help=f"Port for the status monitor website (default: {monitor_server.DEFAULT_MONITOR_PORT}, or env $MONITOR_PORT)",
    )
    parser.add_argument(
        "--no-monitor",
        action="store_true",
        default=os.getenv("DISABLE_MONITOR", "false").lower() in ("true", "1", "yes"),
        help="Disable the secondary status monitor website",
    )
    return parser.parse_args()


def run_server() -> None:
    """Initialize and run the HTTP/HTTPS server and monitor server."""
    args = parse_arguments()
    server_address = (args.host, args.port)

    httpd = CodeGenServer(
        server_address,
        CodeGenRequestHandler,
        default_length=args.length,
        default_charset=args.charset,
        default_format=args.format,
        storage_dir=args.storage_dir,
        key_bits=args.key_bits,
        inactivity_days=args.inactivity_days,
    )

    proto = "http"
    if args.ssl:
        cert_path, key_path = ensure_self_signed_cert(args.ssl_cert, args.ssl_key)
        if os.path.isfile(cert_path) and os.path.isfile(key_path):
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.load_cert_chain(certfile=cert_path, keyfile=key_path)
            httpd.socket = context.wrap_socket(httpd.socket, server_side=True)
            httpd.is_ssl = True
            proto = "https"
            print(f"  TLS Encryption: ENABLED ({cert_path})")

    # Start background 30-day inactivity monitor thread
    start_inactivity_monitor_thread(httpd, check_interval_seconds=60)

    # Start secondary status monitor website on another port (default: 8081)
    monitor_httpd = None
    if not args.no_monitor:
        try:
            monitor_httpd, _ = monitor_server.start_monitor_server_thread(
                host=args.host,
                port=args.monitor_port,
                storage_dir=args.storage_dir,
                inactivity_days=args.inactivity_days,
            )
        except Exception as e:
            sys.stderr.write(f"[Monitor Server Warning] Could not start monitor website on port {args.monitor_port}: {e}\n")

    def shutdown_handler(signum, frame):
        print("\nShutdown signal received. Shutting down servers gracefully...")
        if monitor_httpd:
            try:
                monitor_httpd.server_close()
            except Exception:
                pass
        httpd.server_close()
        sys.exit(0)

    signal.signal(signal.SIGINT, shutdown_handler)
    signal.signal(signal.SIGTERM, shutdown_handler)

    print(f"============================================================")
    print(f"  SecureVault Server v{SERVER_VERSION} (Switzerland)")
    print(f"  Primary Vault Website: {proto}://{args.host}:{args.port}/")
    print(f"  Vault App Subpage:     {proto}://{args.host}:{args.port}/app")
    if monitor_httpd:
        print(f"  Monitor Website:       http://{args.host}:{args.monitor_port}/")
    print(f"  Language: German (Default/Base) with English Toggle")
    print(f"  Inactivity Timeout: {args.inactivity_days} Days (Dead Man's Switch)")
    print(f"  Storage Directory: {args.storage_dir}")
    print(f"  Encrypted Content: Text and Files (AES-256-GCM Split Keys)")
    print(f"  Email Delivery: {'Configured (Gmail/SMTP)' if email_service.is_smtp_configured() else 'Simulation Mode (Set $SMTP_USER & $SMTP_PASS in .env)'}")
    print(f"  Endpoints: / (Home), /app (Vault), /api/encrypt, /api/decrypt, /api/inherit, /api/heartbeat, /code")
    print(f"============================================================")
    print("Ready to handle requests. Press Ctrl+C to stop.")

    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        shutdown_handler(signal.SIGINT, None)


if __name__ == "__main__":
    run_server()
