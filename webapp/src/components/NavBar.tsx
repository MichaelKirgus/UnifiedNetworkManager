import { NavLink } from 'react-router-dom';
import clsx from 'clsx';

const NAV_ITEMS = [
  { to: '/devices', label: 'Devices' },
  { to: '/config-jobs', label: 'Config Jobs' },
  { to: '/plugins', label: 'Plugins' },
];

export function NavBar() {
  return (
    <header className="border-b border-slate-200 bg-white">
      <div className="mx-auto flex max-w-6xl items-center justify-between px-4 py-3">
        <div className="flex items-center gap-8">
          <span className="text-lg font-bold text-slate-900">UnifiedNetworkManager</span>
          <nav className="flex gap-4">
            {NAV_ITEMS.map((item) => (
              <NavLink
                key={item.to}
                to={item.to}
                className={({ isActive }) =>
                  clsx(
                    'rounded-md px-3 py-1.5 text-sm font-medium transition-colors',
                    isActive ? 'bg-slate-900 text-white' : 'text-slate-600 hover:bg-slate-100'
                  )
                }
              >
                {item.label}
              </NavLink>
            ))}
          </nav>
        </div>
        <button
          className="rounded-md px-3 py-1.5 text-sm font-medium text-slate-600 hover:bg-slate-100"
          onClick={() => {
            localStorage.removeItem('accessToken');
            window.location.href = '/login';
          }}
        >
          Sign out
        </button>
      </div>
    </header>
  );
}
