﻿using MOCDIntegrations.Models;
using Newtonsoft.Json;
using Newtonsoft.Json.Converters;
using System;
using System.Collections.Generic;
using System.Configuration;
using System.IO;
using System.Linq;
using System.Net;
using System.ServiceModel;
using System.ServiceModel.Channels;
using System.Web;
using System.Web.Mvc;
using System.Web.Script.Serialization;
using System.Xml;

namespace MOCDIntegrations.Controllers
{
    public class RAKLEASEController : Controller
    {
        // GET: RAKLEASE
        public ActionResult Index()
        {
            return View("RAKLEASE");
        }

        private string GenerateToken()
        {
            try
            {
                oAuthTokenGeneration obj = new oAuthTokenGeneration();
                TokenDetails tknDetails = obj.GenerateToken(ConfigurationManager.AppSettings["uri"].ToString(), ConfigurationManager.AppSettings["grant_type"].ToString(), ConfigurationManager.AppSettings["client_id"].ToString(), ConfigurationManager.AppSettings["client_secret"].ToString(), ConfigurationManager.AppSettings["scope"].ToString());
                return tknDetails.access_token;
            }
            catch (Exception ex)
            {
                throw ex;
            }
        }

        public ActionResult Search(string postdata, string UserAgent)
        {
            var json = "";
            int flag = 0;

            try
            {
                JsonHelper objHelper = new JsonHelper();
                var input = new JavaScriptSerializer().Deserialize<RAKLEASEDetails.RAKLEASEDetailsRequestParams>(postdata);

                RAKLEASECONTRACT.SI_MOCD_OBClient client = new RAKLEASECONTRACT.SI_MOCD_OBClient();
                using (OperationContextScope scope = new OperationContextScope(client.InnerChannel))
                {
                    var httpRequestProperty = new HttpRequestMessageProperty();
                    httpRequestProperty.Headers[System.Net.HttpRequestHeader.Authorization] = "Bearer " + GenerateToken();
                    OperationContext.Current.OutgoingMessageProperties[HttpRequestMessageProperty.Name] = httpRequestProperty;

                    RAKLEASECONTRACT.SI_MOCD_OBRequest objRequest = new RAKLEASECONTRACT.SI_MOCD_OBRequest();
                    RAKLEASECONTRACT.DT_MOCD_Request objDTRequest = new RAKLEASECONTRACT.DT_MOCD_Request();
                    objDTRequest.Emirates_ID = input.EmiratesId;
                    objRequest.MT_MOCD_Request = objDTRequest;

                    List<RAKLEASEDetails.RAKLEASEDetailsResponseParams> ltsRAKLEASEDetailsResponseParams = new List<RAKLEASEDetails.RAKLEASEDetailsResponseParams>();
                    RAKLEASEDetails.RAKLEASEDetailsResponseParams objRAKLEASEDetailsResponseParams = null;

                    RAKLEASECONTRACT.DT_MOCD_Response objResponse = client.SI_MOCD_OB(objDTRequest);

                    RAKLEASECONTRACT.DT_MOCD_ResponseApi_Errors[] apiErrors = objResponse.Api_Errors;

                    RAKLEASECONTRACT.DT_MOCD_ResponseContractDetails[] contractDetails = objResponse.ContractDetails;


                    if (contractDetails != null && contractDetails.Length > 0)
                    {
                        foreach (RAKLEASECONTRACT.DT_MOCD_ResponseContractDetails objContract in contractDetails)
                        {
                            objRAKLEASEDetailsResponseParams = new RAKLEASEDetails.RAKLEASEDetailsResponseParams();
                            objRAKLEASEDetailsResponseParams.Contractor_Number = objContract.Contractor_Number;
                            objRAKLEASEDetailsResponseParams.Person_Name = objContract.Person_Name;
                            objRAKLEASEDetailsResponseParams.Property_Type = objContract.Property_Type;
                            objRAKLEASEDetailsResponseParams.Location = objContract.Location;
                            objRAKLEASEDetailsResponseParams.Annual_Lease_Amount = objContract.Annual_Lease_Amount;
                            objRAKLEASEDetailsResponseParams.Lease_Duration = objContract.Lease_Duration;
                            objRAKLEASEDetailsResponseParams.Start_Date = objContract.Start_Date;
                            objRAKLEASEDetailsResponseParams.End_Date = objContract.End_Date;
                            objRAKLEASEDetailsResponseParams.Contractor_Type = objContract.Contractor_Type;

                            ltsRAKLEASEDetailsResponseParams.Add(objRAKLEASEDetailsResponseParams);

                        }

                        flag = 1;
                        json = JsonConvert.SerializeObject(new { ltsRAKLEASEDetailsResponseParams, flag }, new IsoDateTimeConverter() { DateTimeFormat = "yyyy-MM-dd HH:mm:ss" });
                        LogIntegrationDetails.LogSerilog(postdata, objHelper.ConvertObjectToJSon<List<RAKLEASEDetails.RAKLEASEDetailsResponseParams>>(ltsRAKLEASEDetailsResponseParams), ConfigurationManager.AppSettings["RAKLEASECode"].ToString(), ConfigurationManager.AppSettings["RAKLEASE"].ToString(), DateTime.Now.ToString(), string.Empty, UserAgent, User.Identity.Name);
                    }
                    else
                    {
                        string ResponseDescription = string.Empty;

                        if (apiErrors != null && apiErrors.Length > 0)
                        {
                            foreach (RAKLEASECONTRACT.DT_MOCD_ResponseApi_Errors apierr in apiErrors)
                            {
                                ResponseDescription += apierr.Message_V1 + " - " + apierr.Message_V2;
                            }
                        }

                        flag = 2;

                        json = JsonConvert.SerializeObject(new { ResponseDescription, flag }, new IsoDateTimeConverter() { DateTimeFormat = "yyyy-MM-dd HH:mm:ss" });

                        LogIntegrationDetails.LogSerilog(postdata, ResponseDescription, ConfigurationManager.AppSettings["RAKLEASECode"].ToString(), ConfigurationManager.AppSettings["RAKLEASE"].ToString(), DateTime.Now.ToString(), string.Empty, UserAgent, User.Identity.Name);
                    }
                }
            }
            catch (FaultException faultException)
            {
                var fault = faultException.CreateMessageFault();
                var doc = new XmlDocument();
                var innerdoc = new XmlDocument();
                var innersdoc = new XmlDocument();
                var nav = doc.CreateNavigator();
                flag = 3;
                string ResponseDescription = string.Empty;

                if (fault.HasDetail)
                {
                    if (nav != null)
                    {
                        using (var writer = nav.AppendChild())
                        {
                            fault.WriteTo(writer, EnvelopeVersion.Soap12);
                        }

                        string str = string.Empty; //do something with it
                        foreach (XmlNode child in doc.DocumentElement.ChildNodes)
                        {

                            if (child.Name == "Code")
                            {
                                innerdoc.LoadXml(child.InnerXml);
                                foreach (XmlNode chd in innerdoc.DocumentElement.ChildNodes)
                                {
                                    // str += "Contact GSB Support.";
                                }
                            }

                            if (child.Name == "Detail")
                            {
                                //innerdoc.LoadXml(child.InnerXml);
                                //foreach (XmlNode chd in innerdoc.DocumentElement.ChildNodes)
                                //{
                                //    if (chd.Name == "errorMessageArField")
                                //    {
                                //        str += chd.InnerText + " - ";
                                //    }
                                //    if (chd.Name == "errorMessageEnField")
                                //    {
                                //        str += chd.InnerText;
                                //    }

                                //    if (chd.Name == "details")
                                //    {
                                //        innersdoc.LoadXml(chd.InnerXml);
                                //        foreach (XmlNode chds in innersdoc.DocumentElement.ChildNodes)
                                //        {
                                //            if (chds.Name == "message")
                                //            {
                                //                str += chd.InnerText;
                                //            }
                                //        }
                                //    }
                                //}

                                str += child.InnerXml;

                            }
                            ResponseDescription += str;
                        }

                    }

                    json = JsonConvert.SerializeObject(new { ResponseDescription, flag }, new IsoDateTimeConverter() { DateTimeFormat = "yyyy-MM-dd HH:mm:ss" });
                    LogIntegrationDetails.LogSerilog(postdata, ResponseDescription, ConfigurationManager.AppSettings["RAKLEASECode"].ToString(), ConfigurationManager.AppSettings["RAKLEASE"].ToString(), DateTime.Now.ToString(), string.Empty, UserAgent, User.Identity.Name);
                }
                else
                {
                    ResponseDescription = faultException.Message;
                    json = JsonConvert.SerializeObject(new { ResponseDescription, flag }, new IsoDateTimeConverter() { DateTimeFormat = "yyyy-MM-dd HH:mm:ss" });
                    LogIntegrationDetails.LogSerilog(postdata, ResponseDescription, ConfigurationManager.AppSettings["RAKLEASECode"].ToString(), ConfigurationManager.AppSettings["RAKLEASE"].ToString(), DateTime.Now.ToString(), string.Empty, UserAgent, User.Identity.Name);
                }
            }
            catch (WebException ex)
            {
                flag = 3;

                var resp = new StreamReader(ex.Response.GetResponseStream()).ReadToEnd();
                string ResponseDescription = resp;
                json = JsonConvert.SerializeObject(new { ResponseDescription, flag }, new IsoDateTimeConverter() { DateTimeFormat = "yyyy-MM-dd HH:mm:ss" });
                LogIntegrationDetails.LogSerilog(postdata, ResponseDescription, ConfigurationManager.AppSettings["RAKLEASECode"].ToString(), ConfigurationManager.AppSettings["RAKLEASE"].ToString(), DateTime.Now.ToString(), string.Empty, UserAgent, User.Identity.Name);
            }
            catch (Exception ex)
            {
                flag = 3;
                string ResponseDescription = ex.Message;
                json = JsonConvert.SerializeObject(new { ResponseDescription, flag }, new IsoDateTimeConverter() { DateTimeFormat = "yyyy-MM-dd HH:mm:ss" });
                LogIntegrationDetails.LogSerilog(postdata, ResponseDescription, ConfigurationManager.AppSettings["RAKLEASECode"].ToString(), ConfigurationManager.AppSettings["RAKLEASE"].ToString(), DateTime.Now.ToString(), string.Empty, UserAgent, User.Identity.Name);
            }
            return Json(json, JsonRequestBehavior.AllowGet);
        }
    }
}
