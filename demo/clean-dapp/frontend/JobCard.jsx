import React from 'react';
import DOMPurify from 'dompurify';

export default function JobCard({ job }) {
  // Sanitize user-provided HTML before rendering
  const cleanDescription = DOMPurify.sanitize(job.description);

  return (
    <div className="border p-4 rounded shadow-md bg-white">
      <h2 className="text-xl font-bold">{job.title}</h2>
      <p className="text-gray-600">Reward: {job.reward} ETH</p>
      
      <div 
        className="mt-2 text-sm text-gray-800"
        dangerouslySetInnerHTML={{ __html: cleanDescription }} 
      />
      
      <button className="mt-4 bg-blue-600 text-white px-4 py-2 rounded">
        Apply Now
      </button>
    </div>
  );
}
