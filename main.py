from fastapi import FastAPI, Query, HTTPException
from typing import Optional, List
from pymongo import MongoClient
from motor.motor_asyncio import AsyncIOMotorClient
import json
from bson import json_util
from dotenv import load_dotenv
import os
from datetime import datetime, timedelta, timezone
from psirt_helpers import get_data_summary, get_issue_age_query, get_sla_query
from mend_helpers import get_mend_sca_data_summary


# load_dotenv()
app = FastAPI()
# database_client = AsyncIOMotorClient(os.getenv("DATABASE_URL"))
# database_client = AsyncIOMotorClient("mongodb://9.30.234.75:27017")
database_client = AsyncIOMotorClient("mongodb://host.docker.internal:27017")
database = database_client["crisp_db"]

@app.get("/api/v1/github-risk/fetch")
async def fetch_github_risk(
    pid: Optional[str] = Query(None),
    severity: Optional[str] = Query(None)
    ):
    query_pid = {"Product Name": pid} if pid else {}
    query_severity = {"Severity": severity} if severity else {}
    query = query_pid | query_severity
    # print(query)
    try:
        data = await database["github_risk"].find(query, {'_id':0}).to_list()
        return{"data": data}
    except Exception as e:
        raise HTTPException (status_code=400, detail="Error occured while getting GitHub Risk data")
    
@app.get("/api/v1/psirt-pvr/fetch")
async def fetch_psirt_pvr(
    pid: Optional[List[str]] = Query(None),
    severity: Optional[List[str]] = Query(None),
    state: Optional[List[str]] = Query(None),
    age: Optional[List[str]] = Query(None),
    sla: Optional[List[str]] = Query(None)
):
    query_pid = {"Product profile": {"$in": pid}} if pid else {}
    query_severity = {"Severity": {"$in": severity}} if severity else {}
    query_state = {"State": {"$in": state}} if state else {}
    query_issue_age = get_issue_age_query(age)
    query_sla_due = get_sla_query(sla)
    query = query_pid | query_severity | query_state | query_issue_age | query_sla_due
    # print(query)
    try:
        data = await database["psirt_pvr"].find(query, {'_id': 0}).to_list()
        summary = get_data_summary(data)
        return {"summary": summary, "data": data}
    except Exception as e:
        raise HTTPException(status_code=400, detail="Error occured while getting PSIRT PVR data from database: " + str(e))
    
@app.get("/api/v1/twistlock/fetch")
async def fetch_twistlock(
    pid: Optional[str] = Query(None),
    severity: Optional[str] = Query(None),
    type: Optional[str] = Query(None)
):
    return {"message": "Work in progress"}

@app.get("/api/v1/mend-sca/fetch")
async def fetch_mend_sca(
    pid: Optional[List[str]] = Query(None),
    severity: Optional[List[str]] = Query(None),
):
    query_pid = {"PID": {"$in": pid}} if pid else {}
    query_severity = {"Severity": {"$in": [s.upper() for s in severity]}} if severity else {}
    query = query_pid | query_severity
    # print(query)
    try:
        data = await database["mend_sca"].find(query, {'_id': 0}).to_list()
        summary = get_mend_sca_data_summary(data)
        return {"summary": summary, "data": data}
    except Exception as e:
        raise HTTPException(status_code=400, detail="Error occured while getting Mend SCA data from database: " + str(e))
    
@app.get("/api/v1/mend-sast/fetch")
async def fetch_mend_sast(
    pid: Optional[List[str]] = Query(None),
    severity: Optional[List[str]] = Query(None)
):
    query_pid = {"PID": {"$in": pid}} if pid else {}
    query_severity = {"Severity": {"$in": severity}} if severity else {}
    query = query_pid | query_severity
    try:
        data = await database["mend_sast"].find(query, {'_id': 0}).to_list()
        # As the data in the summary is same hence using the same function by design
        summary = get_mend_sca_data_summary(data)
        return {"summary": summary, "data": data}
    except Exception as e:
        raise HTTPException(status_code=400, detail="Error occured while getting Mend SCA data from database: " + str(e))
    
@app.get("/api/v1/sos-edr/fetch")
async def fetch_sos_edr():
    try:
        latest_doc = await database["sos_edr_data"].find_one(sort=[("created_at", -1)])
        latest_ts = latest_doc["created_at"] if latest_doc else None
        if latest_ts:
            data = await database["sos_edr_data"].find({"created_at":latest_ts}, {'_id': 0, "created_at": 0}).to_list()
            return {"timestamp": latest_ts, "data": data}
    except Exception as e:
        raise HTTPException(status_code=400, detail="Error occured while fetching EDR data")
    
@app.get("/api/v1/sos-qradar/fetch")
async def fetch_sos_qradar():
    try:
        latest_doc = await database["sos_qradar_data"].find_one(sort=[("created_at", -1)])
        latest_ts = latest_doc["created_at"] if latest_doc else None
        if latest_ts:
            data = await database["sos_qradar_data"].find({"created_at":latest_ts}, {'_id': 0, "created_at": 0}).to_list()
            return {"timestamp": latest_ts, "data": data}
    except Exception as e:
        raise HTTPException(status_code=400, detail="Error occured while fetching QRadar data")
    
@app.get("/api/v1/sos-sys-vuln/fetch")
async def fetch_sos_sys_vuln():
    try:
        latest_doc = await database["sos_sys_vuln_data"].find_one(sort=[("created_at", -1)])
        latest_ts = latest_doc["created_at"] if latest_doc else None
        if latest_ts:
            data = await database["sos_sys_vuln_data"].find({"created_at":latest_ts}, {'_id': 0, "created_at": 0}).to_list()
            return {"timestamp": latest_ts, "data": data}
    except Exception as e:
        raise HTTPException(status_code=400, detail="Error occured while fetching Sys Vulnerability data")
    
@app.get("/api/v1/sos-edr-summary")
async def fetch_sos_edr_summary():
    try:
        start_date = datetime.now(timezone.utc) - timedelta(days=30)
        data = await database["sos_edr_summary"].find({"date_obj":{"$gte":start_date}}, {'_id': 0, "date_obj": 0}, sort=[("date_obj", 1)]).to_list()
        return {"data": data}
    except Exception as e:
        print(str(e))
        raise HTTPException(status_code=400, detail="Error occured while fetching EDR summary data")
    
@app.get("/api/v1/sos-qradar-summary")
async def fetch_sos_qradar_summary():
    try:
        start_date = datetime.now(timezone.utc) - timedelta(days=30)
        data = await database["sos_qradar_summary"].find({"date_obj":{"$gte":start_date}}, {'_id': 0, "date_obj": 0}, sort=[("date_obj", 1)]).to_list()
        return {"data": data}
    except Exception as e:
        raise HTTPException(status_code=400, detail="Error occured while fetching QRadar summary data")
    
@app.get("/api/v1/sos-sys-vuln-summary")
async def fetch_sos_sys_vuln_summary():
    try:
        start_date = datetime.now(timezone.utc) - timedelta(days=30)
        data = await database["sos_sys_vuln_summary"].find({"date_obj":{"$gte":start_date}}, {'_id': 0, "date_obj": 0}, sort=[("date_obj", 1)]).to_list()
        return {"data": data}
    except Exception as e:
        raise HTTPException(status_code=400, detail="Error occured while fetching Sys Vulnrability summary data")
    
@app.get("/api/v1/sos/summary")
async def fetch_sos_summary():
    try:
        start_date = datetime.now(timezone.utc) - timedelta(days=30)
        data_edr = await database["sos_edr_compliance"].find({"date_obj":{"$gte":start_date}}, {'_id': 0, "date_obj": 0}, sort=[("date_obj", 1)]).to_list()
        data_qradar  = await database["sos_qradar_compliance"].find({"date_obj":{"$gte":start_date}}, {'_id': 0, "date_obj": 0}, sort=[("date_obj", 1)]).to_list()
        data_sys_vuln = await database["sos_sys_vuln_compliance"].find({"date_obj":{"$gte":start_date}}, {'_id': 0, "date_obj": 0}, sort=[("date_obj", 1)]).to_list()
        return {"edr_summary": data_edr, "qradar_summary": data_qradar, "sys_vuln_summary": data_sys_vuln}
    except Exception as e:
        raise HTTPException(status_code=400, detail="Error occured while fetching SOS summary")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=9000)