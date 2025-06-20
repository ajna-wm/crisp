def get_data_summary(data):
    summary = {
        "total_count": 0,
        "pid": {
            "IBM webMethods API Management (SaaS)": 0,
            "IBM webMethods B2B (SaaS)": 0,
            "IBM webMethods Integration (SaaS)": 0,
            "IBM webMethods Integration Embed SaaS": 0,
            "IBM webMethods Managed File Transfer (SaaS)": 0,
            "App Connect Enterprise": 0,
            "IBM API Connect Enterprise": 0,
            "IBM Event Endpoint Management": 0
        },
        "severity": {
            "Critical": 0,
            "High": 0,
            "Medium": 0,
            "Low": 0,
            'None': 0
        },
        "state": {
            "Awaiting Implementation": 0,
            "Closed": 0,
            "Closed Not Applicable": 0,
            "Disclosure Required": 0,
            "In Remediation Planning": 0,
            "Needs Assessment": 0
        },
        "age": {
            "0": 0,
            "1": 0,
            "2": 0,
            "3": 0
        },
        "sla": {
            "-1": 0,
            "0": 0,
            "1": 0,
            "2": 0,
            "3": 0,
            "NA": 0
        },
    }
    summary["total_count"] = len(data)
    for row in data:
        summary["severity"][row["Severity"]] += 1
        summary["state"][row["State"]] += 1
        summary["age"][get_age_catagory(row["issue_age"])] += 1
        summary["sla"][get_sla_catagory(row["sla_due"])] += 1
        if row["Product profile"] in ["IBM webMethods API Management (SaaS)", "IBM webMethods B2B (SaaS)", "IBM webMethods Integration (SaaS)", "IBM webMethods Integration Embed SaaS", "IBM webMethods Managed File Transfer (SaaS)"]:
            summary["pid"][row["Product profile"]] += 1
    return summary

def get_issue_age_query(age):
    result = {}
    if age and len(age) == 1:
        if age[0] == "0":
            result = {"issue_age":{"$gt":0, "$lte": 10}}
        elif age[0] == "1":
            result = {"issue_age":{"$gt":10, "$lte": 30}}
        elif age[0] == "2":
            result = {"issue_age":{"$gt":30, "$lte": 60}}
        elif age[0] == "3":
            result = {"issue_age":{"$gt":60}}
    if age and len(age) > 1:
        result = {"$or": []}
        if "0" in age:
            result["$or"].append({"issue_age":{"$gt":0, "$lte": 10}})
        if "1" in age:
            result["$or"].append({"issue_age":{"$gt":10, "$lte": 30}})
        if "2" in age:
            result["$or"].append({"issue_age":{"$gt":30, "$lte": 60}})
        if "3" in age:
            result["$or"].append({"issue_age":{"$gt":60}})
    return result

def get_sla_query(sla):
    result = {}
    if sla and len(sla) == 1:
        if sla[0] == "0":
            result = {"sla_due":{"$gt":0, "$lte": 10}}
        elif sla[0] == "1":
            result = {"sla_due":{"$gt":10, "$lte": 30}}
        elif sla[0] == "2":
            result = {"sla_due":{"$gt":30, "$lte": 60}}
        elif sla[0] == "3":
            result = {"sla_due":{"$gt":60}}
        elif sla[0] == "-1":
            result = {"sla_due": "SLA Breached"}
    if sla and len(sla) > 1:
        result = {"$or": []}
        if "0" in sla:
            result["$or"].append({"sla_due":{"$gt":0, "$lte": 10}})
        if "1" in sla:
            result["$or"].append({"sla_due":{"$gt":10, "$lte": 30}})
        if "2" in sla:
            result["$or"].append({"sla_due":{"$gt":30, "$lte": 60}})
        if "3" in sla:
            result["$or"].append({"sla_due":{"$gt":60}})
        if "-1" in sla:
            result["$or"].append({"sla_due": "SLA Breached"})
    return result

def get_age_catagory(age):
    if age <= 10:
        return "0"
    if age <= 30:
        return "1"
    if age <= 60:
        return "2"
    if age > 60:
        return "3"
    
def get_sla_catagory(sla):
    if sla == "SLA Breached":
        return "-1"
    if sla == "NA":
        return "NA"
    if sla <= 10:
        return "0"
    if sla <= 30:
        return "1"
    if sla <= 60:
        return "2"
    if sla > 60:
        return "3"