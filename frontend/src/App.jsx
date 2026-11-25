import React, { useEffect, useRef, useState } from 'react';
import { Navigate, Route, Routes, useLocation } from 'react-router-dom';
import {
  analyzeSample,
  fetchHealth,
  fetchSamples,
  fetchSessions,
  fetchTestbedStatus,
  uploadPcap,
} from './api';
import { Layout } from './components/Layout';
import { HomePage } from './pages/HomePage';
import { OverviewPage } from './pages/OverviewPage';
import { InspectorPage } from './pages/InspectorPage';
import { TrafficLabPage } from './pages/TrafficLabPage';
import { ScannerPage } from './pages/ScannerPage';
import { RemediationPage } from './pages/RemediationPage';

export default function App() {
  const [samples, setSamples] = useState([]);
  const [sessions, setSessions] = useState([]);
  const [testbedStatus, setTestbedStatus] = useState({ docker_running: false, containers: [] });
  const [health, setHealth] = useState(null);
  const [analysis, setAnalysis] = useState(null);
  const [loading, setLoading] = useState(false);
  const [toast, setToast] = useState(null);
  const fileInputRef = useRef(null);
  const toastTimerRef = useRef(null);
  const location = useLocation();

  useEffect(() => {
    window.scrollTo({ top: 0, behavior: 'auto' });
  }, [location.pathname]);

  const showToast = (msg, type = 'info') => {
    setToast({ msg, type });
    if (toastTimerRef.current) clearTimeout(toastTimerRef.current);
    toastTimerRef.current = setTimeout(() => setToast(null), 3500);
  };

  const refreshMetadata = async () => {
    try {
      const [h, s, tb, sess] = await Promise.all([
        fetchHealth(),
        fetchSamples(),
        fetchTestbedStatus(),
        fetchSessions(),
      ]);
      setHealth(h);
      setSamples(s);
      setTestbedStatus(tb);
      setSessions(sess);
      return s;
    } catch {
      showToast('Backend connection error', 'error');
      return [];
    }
  };

  const handleSampleClick = async (filename) => {
    setLoading(true);
    try {
      const res = await analyzeSample(filename);
      setAnalysis(res);
      setSessions(await fetchSessions());
      showToast(`Analyzed ${filename}`, 'success');
    } catch (err) {
      showToast(err.message, 'error');
    } finally {
      setLoading(false);
    }
  };

  const handleFileUpload = async (file) => {
    if (!file) return;
    setLoading(true);
    try {
      const res = await uploadPcap(file);
      setAnalysis(res);
      setSessions(await fetchSessions());
      showToast(`Uploaded & analyzed ${file.name}`, 'success');
    } catch (err) {
      showToast(`Upload failed: ${err.message}`, 'error');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    refreshMetadata().then((loadedSamples) => {
      if (loadedSamples.length > 0) {
        const defaultSample =
          loadedSamples.find((x) => x.filename.includes('hardened_ikev2_tunnel_web')) || loadedSamples[0];
        handleSampleClick(defaultSample.filename);
      }
    });
  }, []);

  const triggerUpload = () => fileInputRef.current?.click();

  return (
    <>
      <input
        ref={fileInputRef}
        type="file"
        accept=".pcap,.pcapng,.cap"
        className="hidden"
        onChange={(e) => {
          const picked = e.target.files?.[0];
          if (picked) {
            handleFileUpload(picked);
            e.target.value = '';
          }
        }}
      />

      <Layout
        analysis={analysis}
        samples={samples}
        health={health}
        testbedStatus={testbedStatus}
        loading={loading}
        toast={toast}
        onSelectSample={handleSampleClick}
        onTriggerUpload={triggerUpload}
      >
        <Routes>
          <Route
            path="/"
            element={
              <HomePage
                analysis={analysis}
                samples={samples}
                loading={loading}
                onSelectSample={handleSampleClick}
                onUploadFile={handleFileUpload}
                onTriggerUpload={triggerUpload}
              />
            }
          />
          <Route path="/overview" element={<OverviewPage analysis={analysis} />} />
          <Route path="/inspector" element={<InspectorPage analysis={analysis} />} />
          <Route path="/traffic-lab" element={<TrafficLabPage analysis={analysis} />} />
          <Route path="/scanner" element={<ScannerPage onToast={showToast} />} />
          <Route
            path="/remediation"
            element={
              <RemediationPage analysis={analysis} sessions={sessions} onToast={showToast} />
            }
          />
          <Route path="*" element={<Navigate to="/" replace />} />
        </Routes>
      </Layout>
    </>
  );
}
