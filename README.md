# Personal-Budget-Transactions
---
**Group Members**: Hung Pham Viet, Zainul Hasan Syed Mohammed
---

## Project Overview
In My Pocket is a forward-looking personal finance web app designed around one simple question — ***“How much can I spend right now?”***
The application provides live visibility into your disposable income by continuously reconciling income, expenses, goals, and savings.
It helps users plan proactively, visualize their financial health, and make confident spending decisions — all from a unified dashboard.

--- 
## Core Value Propostion
- Provide a centralized financial control surface for end users.
- Transform raw transactions into meaningful analytics leveraging.
- Maintain a low‑overhead, fully portable footprint using SQLite.
- Enable fast onboarding and minimal cognitive friction.
  
## Insightful Visualizations
1. Dashboard Insights
- A unified landing experience presenting:
- Monthly spend vs. income deltas.
- Category-level pie chart
- Cumulative spending/income curves
- Cashflow Network
- Visual feedback to help users identify overspending or underfunded goals.
- Recent Transactions
- and Real‑time data visualizations powered by Chart.js.
  
2. Transaction Management
- Add, update, and delete income or expense entries through streamlined forms.
- Categorization via predefined or user‑generated categories.
- Full CRUD workflows backed by SQLite persistence.

3. Budget Controls
- Define monthly caps per category or for the overall budget.
- Automated alerts when thresholds approach or exceed limits.
- Historical comparison for trend visibility.

---
## Tools and Technologies
| Layer                               | Technology             | Purpose                                             |
| ----------------------------------- | ---------------------- | --------------------------------------------------- |
| **Programming Language**            | Python                 | Core application logic                              |
| **Backend Framework**               | Flask                  | Lightweight REST API and server logic            |
| **Frontend Framework**              | Chart.js, HTML         | Responsive and clean web interface                  |
| **Database**                        | SQLite /               | Persistent data storage                          
## Architecture Overview
```
root
├── database
│   ├── database.py
│   └── App.db
├── templates
│   ├── index.html
│   ├── dashboard.html
│   ├── add_transaction.html
│   ├── edit_transaction.html
│   └── ...
├── src
│   └── web-app.py
```

## Usage Workflow
1. Register or log in to establish a session.
2. Add income and expense transactions through the interface.
3. Configure or adjust monthly budget parameters.
4. Access the analytics dashboard to review visual outputs.
5. Iterate based on insights — adjust budgets, re-categorize transactions


