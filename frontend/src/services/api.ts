/**
 * API client for SIP Sherlock backend.
 * Handles text analysis, file upload, and sample trace fetching.
 * Returns structured error detail for rich UI display.
 */

import axios from 'axios';
import type { AnalysisResult } from '../types/analysis.types';

const API_BASE = '';

const api = axios.create({
  baseURL: API_BASE,
  timeout: 60000, // 60s for AI-powered analysis
});

/**
 * Structured error shape returned by analyze functions.
 */
export interface AnalysisError {
  code: string;
  message: string;
  hints: string[];
  first_line_detected: string | null;
  total_lines?: number;
}

/**
 * Extract a structured error from an Axios error.
 * Handles the new backend error format with hints + first_line_detected.
 */
function extractStructuredError(err: any): AnalysisError {
  const detail = err?.response?.data?.detail;

  if (detail && typeof detail === 'object' && detail.message) {
    return {
      code: detail.error || 'UNKNOWN',
      message: detail.message,
      hints: detail.hints || [],
      first_line_detected: detail.first_line_detected || detail.first_line_preview || null,
      total_lines: detail.total_lines || detail.input_lines || 0,
    };
  }

  if (detail && typeof detail === 'string') {
    return {
      code: 'BACKEND_ERROR',
      message: detail,
      hints: [],
      first_line_detected: null,
    };
  }

  if (err?.code === 'ECONNABORTED') {
    return {
      code: 'TIMEOUT',
      message: 'Request timed out. The analysis is taking too long.',
      hints: ['Try a smaller SIP trace', 'Check that the backend server is responsive'],
      first_line_detected: null,
    };
  }

  if (err?.code === 'ERR_NETWORK' || err?.code === 'ECONNREFUSED') {
    return {
      code: 'BACKEND_OFFLINE',
      message: 'Cannot connect to SIP Sherlock backend server',
      hints: [
        'Start the backend: cd backend && uvicorn main:app --reload --port 8000',
        'Confirm backend is running at http://localhost:8000',
        'Check terminal for Python errors',
      ],
      first_line_detected: null,
    };
  }

  return {
    code: 'NETWORK_ERROR',
    message: err?.message || 'Analysis failed. Please try again.',
    hints: ['Check backend logs for details'],
    first_line_detected: null,
  };
}

/**
 * Extract a user-friendly error message string from an Axios error.
 * Used for backward compatibility where only a string is expected.
 */
function extractErrorMessage(err: any): string {
  const structured = extractStructuredError(err);
  let msg = structured.message;
  if (structured.hints.length > 0) {
    msg += '\n\n' + structured.hints.map((h: string) => `→ ${h}`).join('\n');
  }
  if (structured.first_line_detected) {
    msg += `\n\nFirst line detected: "${structured.first_line_detected}"`;
  }
  return msg;
}

export async function analyzeText(sipText: string): Promise<AnalysisResult> {
  try {
    const response = await api.post<AnalysisResult>('/api/analyze/text', {
      sip_text: sipText,
    });
    return response.data;
  } catch (err: any) {
    throw new Error(extractErrorMessage(err));
  }
}

export async function analyzeFile(file: File): Promise<AnalysisResult> {
  try {
    const formData = new FormData();
    formData.append('file', file);
    const response = await api.post<AnalysisResult>('/api/analyze/file', formData, {
      headers: { 'Content-Type': 'multipart/form-data' },
    });
    return response.data;
  } catch (err: any) {
    throw new Error(extractErrorMessage(err));
  }
}

export async function getSample(sampleId: string): Promise<string> {
  const response = await api.get<{ sip_text: string }>(`/api/samples/${sampleId}`);
  return response.data.sip_text;
}

export async function healthCheck(): Promise<boolean> {
  try {
    const response = await api.get('/api/health');
    return response.data.status === 'ok';
  } catch {
    return false;
  }
}
