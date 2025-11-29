# Personal-Budget-Transactions
---
**Group Members**: Hung Pham Viet, Zainul Hasan Syed Mohammed
---

## Project Overview
In My Pocket is a forward-looking personal finance web app designed around one simple question — ***“How much can I spend right now?”***
The application provides live visibility into your disposable income by continuously reconciling income, expenses, goals, and savings.
It helps users plan proactively, visualize their financial health, and make confident spending decisions — all from a unified dashboard.


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


## Tools and Technologies
| Layer                               | Technology             | Purpose                                             |
| ----------------------------------- | ---------------------- | --------------------------------------------------- |
| **Programming Language**            | Python                 | Core application logic                              |
| **Backend Framework**               | Flask                  | Lightweight REST API and server logic               |
| **Frontend Framework**              | Chart.js, HTML         | Responsive and clean web interface                  |
| **Database**                        | SQLite /               | Persistent data storage                             |

## Architecture Overview
```
root
├── database
│   ├── database.py
│   └── dataframe.py
├── dataset
│   ├── personal-finance-budgeting-records-with-user-info.csv
│   ├── final_df.csv
│   ├── final_records.csv
│   └── final_user.csv
├── src
│   ├── web-app.py
│   ├── App.db
│   └── templates
│       ├── base.html
│       ├── index.html
│       ├── dashboard.html
│       ├── add_records.html
│       ├── add_user_details.html
│       ├── forgot_password.html
│       ├── get_records.html
│       ├── login.html
│       ├── signup.html
│       ├── update_records.html
│       ├── update_user_details.html
│       └── user.html
```

## Usage Workflow
1. Register or log in to establish a session.
2. Add income and expense transactions through the interface.
3. Add user details
4. Configure or adjust monthly budget parameters. 
5. Access the analytics dashboard to review visual outputs. 
6. Iterate based on insights — adjust budgets, re-categorize transactions

## How to Run the Program
1. Only run web-app.py
2. Create Account
3. Log In 
4. Add user details
5. Update user details if needed 
6. Add records 
7. View records
8. Search records
9. Filter records
10. Delete records
11. Update records
12. Click Dashboard
13. View Dashboard
14. Filter in Dashboard

## Note: 
The dataset `personal-finance-budgeting-records-with-user-info` is provided solely as a conceptual artifact to illustrate expected database behavior and data flow. It is not intended for use in production or as real user information. If you plan to integrate it into the database layer for testing or demonstration purposes, annotate the relevant sections to clearly indicate that the dataset consists of simulated, non-sensitive sample data.
