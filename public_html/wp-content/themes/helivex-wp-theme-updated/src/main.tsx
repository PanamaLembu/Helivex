import React from 'react';
import ReactDOM from 'react-dom/client';
import MedicalCore from '../../src/components/MedicalCore';

const medicalCoreRoot = document.getElementById('medical-core-root');
if (medicalCoreRoot) {
  ReactDOM.createRoot(medicalCoreRoot).render(
    <React.StrictMode>
      <MedicalCore />
    </React.StrictMode>
  );
}
