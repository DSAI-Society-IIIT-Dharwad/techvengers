import React from 'react';
import Link from 'next/link';

const GalleryPage = () => {
  return (
    <div className="container mx-auto p-8">
      <h1 className="text-3xl font-bold mb-8 text-center">Our Jewellery Collections</h1>
      <div className="grid grid-cols-1 md:grid-cols-3 gap-8">
        {/* Women Jewellery Card */}
        <Link href="/dashboard/gallery/women" className="bg-white rounded-lg shadow-md overflow-hidden hover:scale-105 transition-transform">
          <img src="https://images.unsplash.com/photo-1517841905240-472988babdf9?auto=format&fit=crop&w=600&q=80" alt="Women Jewellery" className="w-full h-64 object-cover"/>
          <div className="p-4 text-center">
            <h2 className="text-xl font-semibold">Women Jewellery</h2>
          </div>
        </Link>

        {/* Men Jewellery Card */}
        <Link href="/dashboard/gallery/men" className="bg-white rounded-lg shadow-md overflow-hidden hover:scale-105 transition-transform">
          <img src="https://images.unsplash.com/photo-1529626455594-4ff0802cfb7e?auto=format&fit=crop&w=600&q=80" alt="Men Jewellery" className="w-full h-64 object-cover"/>
          <div className="p-4 text-center">
            <h2 className="text-xl font-semibold">Men Jewellery</h2>
          </div>
        </Link>

        {/* Kids Jewellery Card */}
        <Link href="/dashboard/gallery/kids" className="bg-white rounded-lg shadow-md overflow-hidden hover:scale-105 transition-transform">
          <img src="https://images.unsplash.com/photo-1508214751196-bcfd4ca60f91?auto=format&fit=crop&w=600&q=80" alt="Kids Jewellery" className="w-full h-64 object-cover"/>
          <div className="p-4 text-center">
            <h2 className="text-xl font-semibold">Kids Jewellery</h2>
          </div>
        </Link>
      </div>
    </div>
  );
};

export default GalleryPage; 