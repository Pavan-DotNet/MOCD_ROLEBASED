﻿//------------------------------------------------------------------------------
// <auto-generated>
//     This code was generated by a tool.
//     Runtime Version:4.0.30319.42000
//
//     Changes to this file may cause incorrect behavior and will be lost if
//     the code is regenerated.
// </auto-generated>
//------------------------------------------------------------------------------

namespace MOCDIntegrations.DOFPENSION {
    
    
    /// <remarks/>
    [System.CodeDom.Compiler.GeneratedCodeAttribute("System.Xml", "4.7.3062.0")]
    [System.SerializableAttribute()]
    [System.Diagnostics.DebuggerStepThroughAttribute()]
    [System.ComponentModel.DesignerCategoryAttribute("code")]
    [System.Xml.Serialization.XmlTypeAttribute(AnonymousType=true, Namespace="http://ws.wso2.org/dataservice")]
    public partial class DataServiceFault : object, System.ComponentModel.INotifyPropertyChanged {
        
        private string current_paramsField;
        
        private string current_request_nameField;
        
        private string nested_exceptionField;
        
        private DataServiceFaultSource_data_service source_data_serviceField;
        
        private string ds_codeField;
        
        /// <remarks/>
        [System.Xml.Serialization.XmlElementAttribute(Order=0)]
        public string current_params {
            get {
                return this.current_paramsField;
            }
            set {
                this.current_paramsField = value;
                this.RaisePropertyChanged("current_params");
            }
        }
        
        /// <remarks/>
        [System.Xml.Serialization.XmlElementAttribute(Order=1)]
        public string current_request_name {
            get {
                return this.current_request_nameField;
            }
            set {
                this.current_request_nameField = value;
                this.RaisePropertyChanged("current_request_name");
            }
        }
        
        /// <remarks/>
        [System.Xml.Serialization.XmlElementAttribute(Order=2)]
        public string nested_exception {
            get {
                return this.nested_exceptionField;
            }
            set {
                this.nested_exceptionField = value;
                this.RaisePropertyChanged("nested_exception");
            }
        }
        
        /// <remarks/>
        [System.Xml.Serialization.XmlElementAttribute(Order=3)]
        public DataServiceFaultSource_data_service source_data_service {
            get {
                return this.source_data_serviceField;
            }
            set {
                this.source_data_serviceField = value;
                this.RaisePropertyChanged("source_data_service");
            }
        }
        
        /// <remarks/>
        [System.Xml.Serialization.XmlElementAttribute(Order=4)]
        public string ds_code {
            get {
                return this.ds_codeField;
            }
            set {
                this.ds_codeField = value;
                this.RaisePropertyChanged("ds_code");
            }
        }
        
        public event System.ComponentModel.PropertyChangedEventHandler PropertyChanged;
        
        protected void RaisePropertyChanged(string propertyName) {
            System.ComponentModel.PropertyChangedEventHandler propertyChanged = this.PropertyChanged;
            if ((propertyChanged != null)) {
                propertyChanged(this, new System.ComponentModel.PropertyChangedEventArgs(propertyName));
            }
        }
    }
    
    /// <remarks/>
    [System.CodeDom.Compiler.GeneratedCodeAttribute("System.Xml", "4.7.3062.0")]
    [System.SerializableAttribute()]
    [System.Diagnostics.DebuggerStepThroughAttribute()]
    [System.ComponentModel.DesignerCategoryAttribute("code")]
    [System.Xml.Serialization.XmlTypeAttribute(AnonymousType=true, Namespace="http://ws.wso2.org/dataservice")]
    public partial class DataServiceFaultSource_data_service : object, System.ComponentModel.INotifyPropertyChanged {
        
        private string locationField;
        
        private string default_namespaceField;
        
        private string descriptionField;
        
        private string data_service_nameField;
        
        /// <remarks/>
        [System.Xml.Serialization.XmlElementAttribute(Order=0)]
        public string location {
            get {
                return this.locationField;
            }
            set {
                this.locationField = value;
                this.RaisePropertyChanged("location");
            }
        }
        
        /// <remarks/>
        [System.Xml.Serialization.XmlElementAttribute(Order=1)]
        public string default_namespace {
            get {
                return this.default_namespaceField;
            }
            set {
                this.default_namespaceField = value;
                this.RaisePropertyChanged("default_namespace");
            }
        }
        
        /// <remarks/>
        [System.Xml.Serialization.XmlElementAttribute(Order=2)]
        public string description {
            get {
                return this.descriptionField;
            }
            set {
                this.descriptionField = value;
                this.RaisePropertyChanged("description");
            }
        }
        
        /// <remarks/>
        [System.Xml.Serialization.XmlElementAttribute(Order=3)]
        public string data_service_name {
            get {
                return this.data_service_nameField;
            }
            set {
                this.data_service_nameField = value;
                this.RaisePropertyChanged("data_service_name");
            }
        }
        
        public event System.ComponentModel.PropertyChangedEventHandler PropertyChanged;
        
        protected void RaisePropertyChanged(string propertyName) {
            System.ComponentModel.PropertyChangedEventHandler propertyChanged = this.PropertyChanged;
            if ((propertyChanged != null)) {
                propertyChanged(this, new System.ComponentModel.PropertyChangedEventArgs(propertyName));
            }
        }
    }
    
    /// <remarks/>
    [System.CodeDom.Compiler.GeneratedCodeAttribute("System.Xml", "4.7.3062.0")]
    [System.SerializableAttribute()]
    [System.Diagnostics.DebuggerStepThroughAttribute()]
    [System.ComponentModel.DesignerCategoryAttribute("code")]
    [System.Xml.Serialization.XmlTypeAttribute(Namespace="http://ws.wso2.org/dataservice")]
    public partial class Entry : object, System.ComponentModel.INotifyPropertyChanged {
        
        private string pENSIONER_NAME_ARField;
        
        private string pENSIONER_NAME_USField;
        
        private string pENSION_START_DATEField;
        
        private string pENSION_AMOUNTField;
        
        private string pENSION_IDField;
        
        private string pENSIONER_DEATHField;
        
        private string eMIRATES_IDField;
        
        /// <remarks/>
        [System.Xml.Serialization.XmlElementAttribute(IsNullable=true, Order=0)]
        public string PENSIONER_NAME_AR {
            get {
                return this.pENSIONER_NAME_ARField;
            }
            set {
                this.pENSIONER_NAME_ARField = value;
                this.RaisePropertyChanged("PENSIONER_NAME_AR");
            }
        }
        
        /// <remarks/>
        [System.Xml.Serialization.XmlElementAttribute(IsNullable=true, Order=1)]
        public string PENSIONER_NAME_US {
            get {
                return this.pENSIONER_NAME_USField;
            }
            set {
                this.pENSIONER_NAME_USField = value;
                this.RaisePropertyChanged("PENSIONER_NAME_US");
            }
        }
        
        /// <remarks/>
        [System.Xml.Serialization.XmlElementAttribute(IsNullable=true, Order=2)]
        public string PENSION_START_DATE {
            get {
                return this.pENSION_START_DATEField;
            }
            set {
                this.pENSION_START_DATEField = value;
                this.RaisePropertyChanged("PENSION_START_DATE");
            }
        }
        
        /// <remarks/>
        [System.Xml.Serialization.XmlElementAttribute(IsNullable=true, Order=3)]
        public string PENSION_AMOUNT {
            get {
                return this.pENSION_AMOUNTField;
            }
            set {
                this.pENSION_AMOUNTField = value;
                this.RaisePropertyChanged("PENSION_AMOUNT");
            }
        }
        
        /// <remarks/>
        [System.Xml.Serialization.XmlElementAttribute(IsNullable=true, Order=4)]
        public string PENSION_ID {
            get {
                return this.pENSION_IDField;
            }
            set {
                this.pENSION_IDField = value;
                this.RaisePropertyChanged("PENSION_ID");
            }
        }
        
        /// <remarks/>
        [System.Xml.Serialization.XmlElementAttribute(IsNullable=true, Order=5)]
        public string PENSIONER_DEATH {
            get {
                return this.pENSIONER_DEATHField;
            }
            set {
                this.pENSIONER_DEATHField = value;
                this.RaisePropertyChanged("PENSIONER_DEATH");
            }
        }
        
        /// <remarks/>
        [System.Xml.Serialization.XmlElementAttribute(IsNullable=true, Order=6)]
        public string EMIRATES_ID {
            get {
                return this.eMIRATES_IDField;
            }
            set {
                this.eMIRATES_IDField = value;
                this.RaisePropertyChanged("EMIRATES_ID");
            }
        }
        
        public event System.ComponentModel.PropertyChangedEventHandler PropertyChanged;
        
        protected void RaisePropertyChanged(string propertyName) {
            System.ComponentModel.PropertyChangedEventHandler propertyChanged = this.PropertyChanged;
            if ((propertyChanged != null)) {
                propertyChanged(this, new System.ComponentModel.PropertyChangedEventArgs(propertyName));
            }
        }
    }
    
    [System.CodeDom.Compiler.GeneratedCodeAttribute("System.ServiceModel", "4.0.0.0")]
    [System.ServiceModel.ServiceContractAttribute(Namespace="http://ws.wso2.org/dataservice", ConfigurationName="DOFPENSION.PensionInquiryDetailsPortType")]
    public interface PensionInquiryDetailsPortType {
        
        // CODEGEN: Generating message contract since the wrapper name (Entries) of message pensionDetailsPerEmiratesIDResponse does not match the default value (pensionDetailsPerEmiratesID)
        [System.ServiceModel.OperationContractAttribute(Action="urn:pensionDetailsPerEmiratesID", ReplyAction="urn:pensionDetailsPerEmiratesIDResponse")]
        [System.ServiceModel.FaultContractAttribute(typeof(MOCDIntegrations.DOFPENSION.DataServiceFault), Action="urn:pensionDetailsPerEmiratesIDDataServiceFault", Name="DataServiceFault")]
        [System.ServiceModel.XmlSerializerFormatAttribute(SupportFaults=true)]
        MOCDIntegrations.DOFPENSION.pensionDetailsPerEmiratesIDResponse pensionDetailsPerEmiratesID(MOCDIntegrations.DOFPENSION.pensionDetailsPerEmiratesIDRequest request);
        
        [System.ServiceModel.OperationContractAttribute(Action="urn:pensionDetailsPerEmiratesID", ReplyAction="urn:pensionDetailsPerEmiratesIDResponse")]
        System.Threading.Tasks.Task<MOCDIntegrations.DOFPENSION.pensionDetailsPerEmiratesIDResponse> pensionDetailsPerEmiratesIDAsync(MOCDIntegrations.DOFPENSION.pensionDetailsPerEmiratesIDRequest request);
    }
    
    [System.Diagnostics.DebuggerStepThroughAttribute()]
    [System.CodeDom.Compiler.GeneratedCodeAttribute("System.ServiceModel", "4.0.0.0")]
    [System.ComponentModel.EditorBrowsableAttribute(System.ComponentModel.EditorBrowsableState.Advanced)]
    [System.ServiceModel.MessageContractAttribute(WrapperName="pensionDetailsPerEmiratesID", WrapperNamespace="http://ws.wso2.org/dataservice", IsWrapped=true)]
    public partial class pensionDetailsPerEmiratesIDRequest {
        
        [System.ServiceModel.MessageBodyMemberAttribute(Namespace="http://ws.wso2.org/dataservice", Order=0)]
        [System.Xml.Serialization.XmlElementAttribute(IsNullable=true)]
        public string p_emirates_id;
        
        public pensionDetailsPerEmiratesIDRequest() {
        }
        
        public pensionDetailsPerEmiratesIDRequest(string p_emirates_id) {
            this.p_emirates_id = p_emirates_id;
        }
    }
    
    [System.Diagnostics.DebuggerStepThroughAttribute()]
    [System.CodeDom.Compiler.GeneratedCodeAttribute("System.ServiceModel", "4.0.0.0")]
    [System.ComponentModel.EditorBrowsableAttribute(System.ComponentModel.EditorBrowsableState.Advanced)]
    [System.ServiceModel.MessageContractAttribute(WrapperName="Entries", WrapperNamespace="http://ws.wso2.org/dataservice", IsWrapped=true)]
    public partial class pensionDetailsPerEmiratesIDResponse {
        
        [System.ServiceModel.MessageBodyMemberAttribute(Namespace="http://ws.wso2.org/dataservice", Order=0)]
        [System.Xml.Serialization.XmlElementAttribute("Entry")]
        public MOCDIntegrations.DOFPENSION.Entry[] Entry;
        
        public pensionDetailsPerEmiratesIDResponse() {
        }
        
        public pensionDetailsPerEmiratesIDResponse(MOCDIntegrations.DOFPENSION.Entry[] Entry) {
            this.Entry = Entry;
        }
    }
    
    [System.CodeDom.Compiler.GeneratedCodeAttribute("System.ServiceModel", "4.0.0.0")]
    public interface PensionInquiryDetailsPortTypeChannel : MOCDIntegrations.DOFPENSION.PensionInquiryDetailsPortType, System.ServiceModel.IClientChannel {
    }
    
    [System.Diagnostics.DebuggerStepThroughAttribute()]
    [System.CodeDom.Compiler.GeneratedCodeAttribute("System.ServiceModel", "4.0.0.0")]
    public partial class PensionInquiryDetailsPortTypeClient : System.ServiceModel.ClientBase<MOCDIntegrations.DOFPENSION.PensionInquiryDetailsPortType>, MOCDIntegrations.DOFPENSION.PensionInquiryDetailsPortType {
        
        public PensionInquiryDetailsPortTypeClient() {
        }
        
        public PensionInquiryDetailsPortTypeClient(string endpointConfigurationName) : 
                base(endpointConfigurationName) {
        }
        
        public PensionInquiryDetailsPortTypeClient(string endpointConfigurationName, string remoteAddress) : 
                base(endpointConfigurationName, remoteAddress) {
        }
        
        public PensionInquiryDetailsPortTypeClient(string endpointConfigurationName, System.ServiceModel.EndpointAddress remoteAddress) : 
                base(endpointConfigurationName, remoteAddress) {
        }
        
        public PensionInquiryDetailsPortTypeClient(System.ServiceModel.Channels.Binding binding, System.ServiceModel.EndpointAddress remoteAddress) : 
                base(binding, remoteAddress) {
        }
        
        [System.ComponentModel.EditorBrowsableAttribute(System.ComponentModel.EditorBrowsableState.Advanced)]
        MOCDIntegrations.DOFPENSION.pensionDetailsPerEmiratesIDResponse MOCDIntegrations.DOFPENSION.PensionInquiryDetailsPortType.pensionDetailsPerEmiratesID(MOCDIntegrations.DOFPENSION.pensionDetailsPerEmiratesIDRequest request) {
            return base.Channel.pensionDetailsPerEmiratesID(request);
        }
        
        public MOCDIntegrations.DOFPENSION.Entry[] pensionDetailsPerEmiratesID(string p_emirates_id) {
            MOCDIntegrations.DOFPENSION.pensionDetailsPerEmiratesIDRequest inValue = new MOCDIntegrations.DOFPENSION.pensionDetailsPerEmiratesIDRequest();
            inValue.p_emirates_id = p_emirates_id;
            MOCDIntegrations.DOFPENSION.pensionDetailsPerEmiratesIDResponse retVal = ((MOCDIntegrations.DOFPENSION.PensionInquiryDetailsPortType)(this)).pensionDetailsPerEmiratesID(inValue);
            return retVal.Entry;
        }
        
        [System.ComponentModel.EditorBrowsableAttribute(System.ComponentModel.EditorBrowsableState.Advanced)]
        System.Threading.Tasks.Task<MOCDIntegrations.DOFPENSION.pensionDetailsPerEmiratesIDResponse> MOCDIntegrations.DOFPENSION.PensionInquiryDetailsPortType.pensionDetailsPerEmiratesIDAsync(MOCDIntegrations.DOFPENSION.pensionDetailsPerEmiratesIDRequest request) {
            return base.Channel.pensionDetailsPerEmiratesIDAsync(request);
        }
        
        public System.Threading.Tasks.Task<MOCDIntegrations.DOFPENSION.pensionDetailsPerEmiratesIDResponse> pensionDetailsPerEmiratesIDAsync(string p_emirates_id) {
            MOCDIntegrations.DOFPENSION.pensionDetailsPerEmiratesIDRequest inValue = new MOCDIntegrations.DOFPENSION.pensionDetailsPerEmiratesIDRequest();
            inValue.p_emirates_id = p_emirates_id;
            return ((MOCDIntegrations.DOFPENSION.PensionInquiryDetailsPortType)(this)).pensionDetailsPerEmiratesIDAsync(inValue);
        }
    }
}