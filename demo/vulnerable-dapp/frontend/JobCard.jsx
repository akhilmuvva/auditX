import React from 'react';

export default function JobCard({ job }) {
  return (
    <div className="border p-4 rounded shadow-md bg-white">
      <h2 className="text-xl font-bold">{job.title}</h2>
      <p className="text-gray-600">Reward: {job.reward} ETH</p>
      
      {/* Vulnerable: dangerouslySetInnerHTML without sanitization */}
      <div 
        className="mt-2 text-sm text-gray-800"
        dangerouslySetInnerHTML={{ __html: job.description }} 
      />
      
      <button className="mt-4 bg-blue-600 text-white px-4 py-2 rounded">
        Apply Now
      </button>
    </div>
  );
}
