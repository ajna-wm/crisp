def get_mend_sca_data_summary(data):
    summary = {
        "severity": {
            "Critical": 0,
            "High": 0,
            "Medium": 0,
            "Low": 0
        },
        "pid": {
            "IBM webMethods API Management (SaaS)": 0,
            "IBM webMethods B2B (SaaS)": 0,
            "IBM webMethods Integration (SaaS)": 0,
            "IBM webMethods Integration Embed SaaS": 0,
            "IBM webMethods Managed File Transfer (SaaS)": 0,
            "App Connect Enterprise": 0,
            "IBM API Connect Enterprise": 0,
            "IBM Event Endpoint Management": 0
        }
    }
    summary["total_count"] = len(data)
    for row in data:
        if row["PID"] in ["IBM webMethods API Management (SaaS)", "IBM webMethods B2B (SaaS)", "IBM webMethods Integration (SaaS)", "IBM webMethods Integration Embed SaaS", "IBM webMethods Managed File Transfer (SaaS)", "App Connect Enterprise", "IBM API Connect Enterprise", "IBM Event Endpoint Management"]:
            summary["pid"][row["PID"]] += 1
        summary["severity"][row["Severity"].capitalize()] += 1
    return summary