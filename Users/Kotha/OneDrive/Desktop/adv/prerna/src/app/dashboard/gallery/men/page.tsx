'use client';
import React, { useState } from 'react';
import { X, ChevronDown, ChevronUp } from 'lucide-react';

const products = [
  'Bangle', 'Bracelet', 'Chain', 'Earrings', 'Finger Ring', 'Kada', 'Others', 'Pendant', 'Pendant with Chain'
];

const fakeJewellery = products.flatMap((product) =>
  Array.from({ length: 3 }).map((_, i) => ({
    product,
    name: `${product} Design ${i + 1}`,
    img: `https://source.unsplash.com/400x400/?jewellery,${product},${i}`
  }))
);

const MenJewelleryPage = () => {
  const [activeFilters, setActiveFilters] = useState<string[]>([]);
  const [drawerOpen, setDrawerOpen] = useState(false);
  const [productOpen, setProductOpen] = useState(true);

  const toggleDrawer = () => setDrawerOpen((open) => !open);

  const toggleProduct = (product: string) => {
    setActiveFilters((prev) =>
      prev.includes(product)
        ? prev.filter((f) => f !== product)
        : [...prev, product]
    );
  };

  const removeFilter = (product: string) => {
    setActiveFilters((prev) => prev.filter((f) => f !== product));
  };

  const filteredJewellery =
    activeFilters.length === 0
      ? fakeJewellery
      : fakeJewellery.filter((item) => activeFilters.includes(item.product));

  return (
    <div className="container mx-auto p-8">
      <h1 className="text-2xl font-bold mb-6 text-blue-800">Men's Products</h1>
      <div className="flex items-center gap-4 mb-6">
        <button
          className="px-4 py-2 rounded-full bg-blue-100 text-blue-800 font-semibold flex items-center gap-2 shadow hover:bg-blue-200 transition"
          onClick={toggleDrawer}
        >
          Filter
          {activeFilters.length > 0 && (
            <span className="ml-2 bg-blue-600 text-white rounded-full px-2 py-0.5 text-xs">{activeFilters.length}</span>
          )}
        </button>
        {activeFilters.map((filter) => (
          <span key={filter} className="flex items-center px-4 py-2 rounded-full bg-blue-200 text-blue-800 font-medium gap-2">
            {filter}
            <button onClick={() => removeFilter(filter)} className="hover:text-blue-600">
              <X size={16} />
            </button>
          </span>
        ))}
      </div>
      {drawerOpen && (
        <div className="fixed inset-0 z-40 flex">
          <div className="fixed inset-0 bg-black/30" onClick={toggleDrawer}></div>
          <aside className="relative w-80 max-w-full h-full bg-white shadow-lg p-6 z-50 animate-slideInLeft flex flex-col">
            <div className="flex items-center justify-between mb-6">
              <h2 className="text-2xl font-serif font-semibold text-blue-900">Filter By</h2>
              <button onClick={toggleDrawer} className="text-blue-800 hover:text-blue-600 bg-blue-50 rounded-full p-1">
                <X size={24} />
              </button>
            </div>
            <div className="mb-4 bg-white rounded-lg">
              <button
                className="w-full flex items-center justify-between px-2 py-3 text-lg font-semibold text-blue-900 focus:outline-none"
                onClick={() => setProductOpen((open) => !open)}
              >
                <span className="flex items-center gap-2">
                  Product
                  {activeFilters.length > 0 && (
                    <span className="bg-gray-100 text-blue-900 rounded-full px-2 py-0.5 text-xs font-semibold ml-1">
                      {activeFilters.length}
                    </span>
                  )}
                </span>
                {productOpen ? <ChevronUp size={20} /> : <ChevronDown size={20} />}
              </button>
              {productOpen && (
                <div className="flex flex-wrap gap-3 px-2 pb-2">
                  {products.map((product) => (
                    <button
                      key={product}
                      onClick={() => toggleProduct(product)}
                      className={`px-4 py-2 rounded-full border text-blue-800 font-medium shadow-sm transition
                        ${activeFilters.includes(product)
                          ? 'border-blue-700 bg-blue-50'
                          : 'border-blue-200 bg-white hover:bg-blue-50'}`}
                    >
                      {product}
                    </button>
                  ))}
                </div>
              )}
            </div>
            <button
              className="mt-auto w-full py-2 bg-blue-600 text-white rounded hover:bg-blue-700 transition"
              onClick={toggleDrawer}
            >
              Apply Filters
            </button>
          </aside>
        </div>
      )}
      <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 lg:grid-cols-4 gap-8 mt-8">
        {filteredJewellery.length === 0 ? (
          <div className="col-span-full text-center text-blue-400 text-lg">No products to display.</div>
        ) : (
          filteredJewellery.map((item, idx) => (
            <div key={idx} className="bg-white rounded-lg shadow p-4 flex flex-col items-center border border-blue-100">
              <img src={item.img} alt={item.name} className="mb-3 rounded-md w-full h-48 object-cover" />
              <div className="font-semibold text-blue-800 mb-1 text-center">{item.name}</div>
              <button className="mt-auto px-4 py-2 bg-purple-300 text-purple-900 opacity-70 rounded hover:opacity-100 transition">View Details</button>
            </div>
          ))
        )}
      </div>
      <style jsx>{`
        .animate-slideInLeft {
          animation: slideInLeft 0.3s cubic-bezier(0.4, 0, 0.2, 1);
        }
        @keyframes slideInLeft {
          from { transform: translateX(-100%); }
          to { transform: translateX(0); }
        }
      `}</style>
    </div>
  );
};

export default MenJewelleryPage; 