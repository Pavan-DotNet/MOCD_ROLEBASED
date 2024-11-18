﻿//------------------------------------------------------------------------------
// <auto-generated>
//     This code was generated by a tool.
//     Runtime Version:4.0.30319.42000
//
//     Changes to this file may cause incorrect behavior and will be lost if
//     the code is regenerated.
// </auto-generated>
//------------------------------------------------------------------------------

namespace MOCDIntegrations.AJREService {
    
    
    [System.CodeDom.Compiler.GeneratedCodeAttribute("System.ServiceModel", "4.0.0.0")]
    [System.ServiceModel.ServiceContractAttribute(Namespace="http://www.informatica.com/dis/ws/", ConfigurationName="AJREService.AJM_RE_getOwnerPropertyDetailsbyEIDPortType")]
    public interface AJM_RE_getOwnerPropertyDetailsbyEIDPortType {
        
        // CODEGEN: Generating message contract since the operation GetOwnerPropertyDetails is neither RPC nor document wrapped.
        [System.ServiceModel.OperationContractAttribute(Action="", ReplyAction="*")]
        [System.ServiceModel.XmlSerializerFormatAttribute(SupportFaults=true)]
        MOCDIntegrations.AJREService.GetOwnerPropertyDetails_Output GetOwnerPropertyDetails(MOCDIntegrations.AJREService.GetOwnerPropertyDetails_Input request);
        
        [System.ServiceModel.OperationContractAttribute(Action="", ReplyAction="*")]
        System.Threading.Tasks.Task<MOCDIntegrations.AJREService.GetOwnerPropertyDetails_Output> GetOwnerPropertyDetailsAsync(MOCDIntegrations.AJREService.GetOwnerPropertyDetails_Input request);
    }
    
    /// <remarks/>
    [System.CodeDom.Compiler.GeneratedCodeAttribute("System.Xml", "4.7.3062.0")]
    [System.SerializableAttribute()]
    [System.Diagnostics.DebuggerStepThroughAttribute()]
    [System.ComponentModel.DesignerCategoryAttribute("code")]
    [System.Xml.Serialization.XmlTypeAttribute(AnonymousType=true, Namespace="http://www.informatica.com/dis/ws/")]
    public partial class GetOwnerPropertyDetails : object, System.ComponentModel.INotifyPropertyChanged {
        
        private string emiratesIDField;
        
        private string previousPropertiesField;
        
        /// <remarks/>
        [System.Xml.Serialization.XmlElementAttribute(Order=0)]
        public string EmiratesID {
            get {
                return this.emiratesIDField;
            }
            set {
                this.emiratesIDField = value;
                this.RaisePropertyChanged("EmiratesID");
            }
        }
        
        /// <remarks/>
        [System.Xml.Serialization.XmlElementAttribute(Order=1)]
        public string PreviousProperties {
            get {
                return this.previousPropertiesField;
            }
            set {
                this.previousPropertiesField = value;
                this.RaisePropertyChanged("PreviousProperties");
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
    [System.Xml.Serialization.XmlTypeAttribute(AnonymousType=true, Namespace="http://www.informatica.com/dis/ws/")]
    public partial class GetOwnerPropertyDetailsResponse : object, System.ComponentModel.INotifyPropertyChanged {
        
        private GetOwnerPropertyDetailsResponseOwnerPropertyDetails[] ownerPropertyDetailsField;
        
        private GetOwnerPropertyDetailsResponseError[] errorField;
        
        /// <remarks/>
        [System.Xml.Serialization.XmlElementAttribute("OwnerPropertyDetails", Order=0)]
        public GetOwnerPropertyDetailsResponseOwnerPropertyDetails[] OwnerPropertyDetails {
            get {
                return this.ownerPropertyDetailsField;
            }
            set {
                this.ownerPropertyDetailsField = value;
                this.RaisePropertyChanged("OwnerPropertyDetails");
            }
        }
        
        /// <remarks/>
        [System.Xml.Serialization.XmlElementAttribute("Error", Order=1)]
        public GetOwnerPropertyDetailsResponseError[] Error {
            get {
                return this.errorField;
            }
            set {
                this.errorField = value;
                this.RaisePropertyChanged("Error");
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
    [System.Xml.Serialization.XmlTypeAttribute(AnonymousType=true, Namespace="http://www.informatica.com/dis/ws/")]
    public partial class GetOwnerPropertyDetailsResponseOwnerPropertyDetails : object, System.ComponentModel.INotifyPropertyChanged {
        
        private string ownerIdentityIdField;
        
        private string ownerNameARField;
        
        private string ownerNameENField;
        
        private string ownerNationalityCodeField;
        
        private GetOwnerPropertyDetailsResponseOwnerPropertyDetailsLandsInfo[] landsInfoField;
        
        private GetOwnerPropertyDetailsResponseOwnerPropertyDetailsUnitsInfo[] unitsInfoField;
        
        /// <remarks/>
        [System.Xml.Serialization.XmlElementAttribute(Order=0)]
        public string OwnerIdentityId {
            get {
                return this.ownerIdentityIdField;
            }
            set {
                this.ownerIdentityIdField = value;
                this.RaisePropertyChanged("OwnerIdentityId");
            }
        }
        
        /// <remarks/>
        [System.Xml.Serialization.XmlElementAttribute(Order=1)]
        public string OwnerNameAR {
            get {
                return this.ownerNameARField;
            }
            set {
                this.ownerNameARField = value;
                this.RaisePropertyChanged("OwnerNameAR");
            }
        }
        
        /// <remarks/>
        [System.Xml.Serialization.XmlElementAttribute(Order=2)]
        public string OwnerNameEN {
            get {
                return this.ownerNameENField;
            }
            set {
                this.ownerNameENField = value;
                this.RaisePropertyChanged("OwnerNameEN");
            }
        }
        
        /// <remarks/>
        [System.Xml.Serialization.XmlElementAttribute(Order=3)]
        public string OwnerNationalityCode {
            get {
                return this.ownerNationalityCodeField;
            }
            set {
                this.ownerNationalityCodeField = value;
                this.RaisePropertyChanged("OwnerNationalityCode");
            }
        }
        
        /// <remarks/>
        [System.Xml.Serialization.XmlElementAttribute("LandsInfo", Order=4)]
        public GetOwnerPropertyDetailsResponseOwnerPropertyDetailsLandsInfo[] LandsInfo {
            get {
                return this.landsInfoField;
            }
            set {
                this.landsInfoField = value;
                this.RaisePropertyChanged("LandsInfo");
            }
        }
        
        /// <remarks/>
        [System.Xml.Serialization.XmlElementAttribute("UnitsInfo", Order=5)]
        public GetOwnerPropertyDetailsResponseOwnerPropertyDetailsUnitsInfo[] UnitsInfo {
            get {
                return this.unitsInfoField;
            }
            set {
                this.unitsInfoField = value;
                this.RaisePropertyChanged("UnitsInfo");
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
    [System.Xml.Serialization.XmlTypeAttribute(AnonymousType=true, Namespace="http://www.informatica.com/dis/ws/")]
    public partial class GetOwnerPropertyDetailsResponseOwnerPropertyDetailsLandsInfo : object, System.ComponentModel.INotifyPropertyChanged {
        
        private string landIdField;
        
        private string landDeedIdField;
        
        private string landOwnershipTypeField;
        
        private string landCreatedAtField;
        
        private string landShareField;
        
        private string landCityARField;
        
        private string landCityENField;
        
        private string landSectorARField;
        
        private string landSectorENField;
        
        private string landDistrictARField;
        
        private string landDistrictENField;
        
        /// <remarks/>
        [System.Xml.Serialization.XmlElementAttribute(Order=0)]
        public string LandId {
            get {
                return this.landIdField;
            }
            set {
                this.landIdField = value;
                this.RaisePropertyChanged("LandId");
            }
        }
        
        /// <remarks/>
        [System.Xml.Serialization.XmlElementAttribute(Order=1)]
        public string LandDeedId {
            get {
                return this.landDeedIdField;
            }
            set {
                this.landDeedIdField = value;
                this.RaisePropertyChanged("LandDeedId");
            }
        }
        
        /// <remarks/>
        [System.Xml.Serialization.XmlElementAttribute(Order=2)]
        public string LandOwnershipType {
            get {
                return this.landOwnershipTypeField;
            }
            set {
                this.landOwnershipTypeField = value;
                this.RaisePropertyChanged("LandOwnershipType");
            }
        }
        
        /// <remarks/>
        [System.Xml.Serialization.XmlElementAttribute(Order=3)]
        public string LandCreatedAt {
            get {
                return this.landCreatedAtField;
            }
            set {
                this.landCreatedAtField = value;
                this.RaisePropertyChanged("LandCreatedAt");
            }
        }
        
        /// <remarks/>
        [System.Xml.Serialization.XmlElementAttribute(Order=4)]
        public string LandShare {
            get {
                return this.landShareField;
            }
            set {
                this.landShareField = value;
                this.RaisePropertyChanged("LandShare");
            }
        }
        
        /// <remarks/>
        [System.Xml.Serialization.XmlElementAttribute(Order=5)]
        public string LandCityAR {
            get {
                return this.landCityARField;
            }
            set {
                this.landCityARField = value;
                this.RaisePropertyChanged("LandCityAR");
            }
        }
        
        /// <remarks/>
        [System.Xml.Serialization.XmlElementAttribute(Order=6)]
        public string LandCityEN {
            get {
                return this.landCityENField;
            }
            set {
                this.landCityENField = value;
                this.RaisePropertyChanged("LandCityEN");
            }
        }
        
        /// <remarks/>
        [System.Xml.Serialization.XmlElementAttribute(Order=7)]
        public string LandSectorAR {
            get {
                return this.landSectorARField;
            }
            set {
                this.landSectorARField = value;
                this.RaisePropertyChanged("LandSectorAR");
            }
        }
        
        /// <remarks/>
        [System.Xml.Serialization.XmlElementAttribute(Order=8)]
        public string LandSectorEN {
            get {
                return this.landSectorENField;
            }
            set {
                this.landSectorENField = value;
                this.RaisePropertyChanged("LandSectorEN");
            }
        }
        
        /// <remarks/>
        [System.Xml.Serialization.XmlElementAttribute(Order=9)]
        public string LandDistrictAR {
            get {
                return this.landDistrictARField;
            }
            set {
                this.landDistrictARField = value;
                this.RaisePropertyChanged("LandDistrictAR");
            }
        }
        
        /// <remarks/>
        [System.Xml.Serialization.XmlElementAttribute(Order=10)]
        public string LandDistrictEN {
            get {
                return this.landDistrictENField;
            }
            set {
                this.landDistrictENField = value;
                this.RaisePropertyChanged("LandDistrictEN");
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
    [System.Xml.Serialization.XmlTypeAttribute(AnonymousType=true, Namespace="http://www.informatica.com/dis/ws/")]
    public partial class GetOwnerPropertyDetailsResponseOwnerPropertyDetailsUnitsInfo : object, System.ComponentModel.INotifyPropertyChanged {
        
        private string unitPropertyIdField;
        
        private string unitProjectIdField;
        
        private string unitMainProjectNameARField;
        
        private string unitMainProjectNameENField;
        
        private string unitShareField;
        
        private string unitCreatedAtField;
        
        /// <remarks/>
        [System.Xml.Serialization.XmlElementAttribute(Order=0)]
        public string UnitPropertyId {
            get {
                return this.unitPropertyIdField;
            }
            set {
                this.unitPropertyIdField = value;
                this.RaisePropertyChanged("UnitPropertyId");
            }
        }
        
        /// <remarks/>
        [System.Xml.Serialization.XmlElementAttribute(Order=1)]
        public string UnitProjectId {
            get {
                return this.unitProjectIdField;
            }
            set {
                this.unitProjectIdField = value;
                this.RaisePropertyChanged("UnitProjectId");
            }
        }
        
        /// <remarks/>
        [System.Xml.Serialization.XmlElementAttribute(Order=2)]
        public string UnitMainProjectNameAR {
            get {
                return this.unitMainProjectNameARField;
            }
            set {
                this.unitMainProjectNameARField = value;
                this.RaisePropertyChanged("UnitMainProjectNameAR");
            }
        }
        
        /// <remarks/>
        [System.Xml.Serialization.XmlElementAttribute(Order=3)]
        public string UnitMainProjectNameEN {
            get {
                return this.unitMainProjectNameENField;
            }
            set {
                this.unitMainProjectNameENField = value;
                this.RaisePropertyChanged("UnitMainProjectNameEN");
            }
        }
        
        /// <remarks/>
        [System.Xml.Serialization.XmlElementAttribute(Order=4)]
        public string UnitShare {
            get {
                return this.unitShareField;
            }
            set {
                this.unitShareField = value;
                this.RaisePropertyChanged("UnitShare");
            }
        }
        
        /// <remarks/>
        [System.Xml.Serialization.XmlElementAttribute(Order=5)]
        public string UnitCreatedAt {
            get {
                return this.unitCreatedAtField;
            }
            set {
                this.unitCreatedAtField = value;
                this.RaisePropertyChanged("UnitCreatedAt");
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
    [System.Xml.Serialization.XmlTypeAttribute(AnonymousType=true, Namespace="http://www.informatica.com/dis/ws/")]
    public partial class GetOwnerPropertyDetailsResponseError : object, System.ComponentModel.INotifyPropertyChanged {
        
        private string inputParameterField;
        
        private string errorCodeField;
        
        private string errorMessageField;
        
        /// <remarks/>
        [System.Xml.Serialization.XmlElementAttribute(Order=0)]
        public string InputParameter {
            get {
                return this.inputParameterField;
            }
            set {
                this.inputParameterField = value;
                this.RaisePropertyChanged("InputParameter");
            }
        }
        
        /// <remarks/>
        [System.Xml.Serialization.XmlElementAttribute(Order=1)]
        public string ErrorCode {
            get {
                return this.errorCodeField;
            }
            set {
                this.errorCodeField = value;
                this.RaisePropertyChanged("ErrorCode");
            }
        }
        
        /// <remarks/>
        [System.Xml.Serialization.XmlElementAttribute(Order=2)]
        public string ErrorMessage {
            get {
                return this.errorMessageField;
            }
            set {
                this.errorMessageField = value;
                this.RaisePropertyChanged("ErrorMessage");
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
    
    [System.Diagnostics.DebuggerStepThroughAttribute()]
    [System.CodeDom.Compiler.GeneratedCodeAttribute("System.ServiceModel", "4.0.0.0")]
    [System.ComponentModel.EditorBrowsableAttribute(System.ComponentModel.EditorBrowsableState.Advanced)]
    [System.ServiceModel.MessageContractAttribute(IsWrapped=false)]
    public partial class GetOwnerPropertyDetails_Input {
        
        [System.ServiceModel.MessageBodyMemberAttribute(Namespace="http://www.informatica.com/dis/ws/", Order=0)]
        public MOCDIntegrations.AJREService.GetOwnerPropertyDetails GetOwnerPropertyDetails;
        
        public GetOwnerPropertyDetails_Input() {
        }
        
        public GetOwnerPropertyDetails_Input(MOCDIntegrations.AJREService.GetOwnerPropertyDetails GetOwnerPropertyDetails) {
            this.GetOwnerPropertyDetails = GetOwnerPropertyDetails;
        }
    }
    
    [System.Diagnostics.DebuggerStepThroughAttribute()]
    [System.CodeDom.Compiler.GeneratedCodeAttribute("System.ServiceModel", "4.0.0.0")]
    [System.ComponentModel.EditorBrowsableAttribute(System.ComponentModel.EditorBrowsableState.Advanced)]
    [System.ServiceModel.MessageContractAttribute(IsWrapped=false)]
    public partial class GetOwnerPropertyDetails_Output {
        
        [System.ServiceModel.MessageBodyMemberAttribute(Namespace="http://www.informatica.com/dis/ws/", Order=0)]
        public MOCDIntegrations.AJREService.GetOwnerPropertyDetailsResponse GetOwnerPropertyDetailsResponse;
        
        public GetOwnerPropertyDetails_Output() {
        }
        
        public GetOwnerPropertyDetails_Output(MOCDIntegrations.AJREService.GetOwnerPropertyDetailsResponse GetOwnerPropertyDetailsResponse) {
            this.GetOwnerPropertyDetailsResponse = GetOwnerPropertyDetailsResponse;
        }
    }
    
    [System.CodeDom.Compiler.GeneratedCodeAttribute("System.ServiceModel", "4.0.0.0")]
    public interface AJM_RE_getOwnerPropertyDetailsbyEIDPortTypeChannel : MOCDIntegrations.AJREService.AJM_RE_getOwnerPropertyDetailsbyEIDPortType, System.ServiceModel.IClientChannel {
    }
    
    [System.Diagnostics.DebuggerStepThroughAttribute()]
    [System.CodeDom.Compiler.GeneratedCodeAttribute("System.ServiceModel", "4.0.0.0")]
    public partial class AJM_RE_getOwnerPropertyDetailsbyEIDPortTypeClient : System.ServiceModel.ClientBase<MOCDIntegrations.AJREService.AJM_RE_getOwnerPropertyDetailsbyEIDPortType>, MOCDIntegrations.AJREService.AJM_RE_getOwnerPropertyDetailsbyEIDPortType {
        
        public AJM_RE_getOwnerPropertyDetailsbyEIDPortTypeClient() {
        }
        
        public AJM_RE_getOwnerPropertyDetailsbyEIDPortTypeClient(string endpointConfigurationName) : 
                base(endpointConfigurationName) {
        }
        
        public AJM_RE_getOwnerPropertyDetailsbyEIDPortTypeClient(string endpointConfigurationName, string remoteAddress) : 
                base(endpointConfigurationName, remoteAddress) {
        }
        
        public AJM_RE_getOwnerPropertyDetailsbyEIDPortTypeClient(string endpointConfigurationName, System.ServiceModel.EndpointAddress remoteAddress) : 
                base(endpointConfigurationName, remoteAddress) {
        }
        
        public AJM_RE_getOwnerPropertyDetailsbyEIDPortTypeClient(System.ServiceModel.Channels.Binding binding, System.ServiceModel.EndpointAddress remoteAddress) : 
                base(binding, remoteAddress) {
        }
        
        [System.ComponentModel.EditorBrowsableAttribute(System.ComponentModel.EditorBrowsableState.Advanced)]
        MOCDIntegrations.AJREService.GetOwnerPropertyDetails_Output MOCDIntegrations.AJREService.AJM_RE_getOwnerPropertyDetailsbyEIDPortType.GetOwnerPropertyDetails(MOCDIntegrations.AJREService.GetOwnerPropertyDetails_Input request) {
            return base.Channel.GetOwnerPropertyDetails(request);
        }
        
        public MOCDIntegrations.AJREService.GetOwnerPropertyDetailsResponse GetOwnerPropertyDetails(MOCDIntegrations.AJREService.GetOwnerPropertyDetails GetOwnerPropertyDetails1) {
            MOCDIntegrations.AJREService.GetOwnerPropertyDetails_Input inValue = new MOCDIntegrations.AJREService.GetOwnerPropertyDetails_Input();
            inValue.GetOwnerPropertyDetails = GetOwnerPropertyDetails1;
            MOCDIntegrations.AJREService.GetOwnerPropertyDetails_Output retVal = ((MOCDIntegrations.AJREService.AJM_RE_getOwnerPropertyDetailsbyEIDPortType)(this)).GetOwnerPropertyDetails(inValue);
            return retVal.GetOwnerPropertyDetailsResponse;
        }
        
        [System.ComponentModel.EditorBrowsableAttribute(System.ComponentModel.EditorBrowsableState.Advanced)]
        System.Threading.Tasks.Task<MOCDIntegrations.AJREService.GetOwnerPropertyDetails_Output> MOCDIntegrations.AJREService.AJM_RE_getOwnerPropertyDetailsbyEIDPortType.GetOwnerPropertyDetailsAsync(MOCDIntegrations.AJREService.GetOwnerPropertyDetails_Input request) {
            return base.Channel.GetOwnerPropertyDetailsAsync(request);
        }
        
        public System.Threading.Tasks.Task<MOCDIntegrations.AJREService.GetOwnerPropertyDetails_Output> GetOwnerPropertyDetailsAsync(MOCDIntegrations.AJREService.GetOwnerPropertyDetails GetOwnerPropertyDetails) {
            MOCDIntegrations.AJREService.GetOwnerPropertyDetails_Input inValue = new MOCDIntegrations.AJREService.GetOwnerPropertyDetails_Input();
            inValue.GetOwnerPropertyDetails = GetOwnerPropertyDetails;
            return ((MOCDIntegrations.AJREService.AJM_RE_getOwnerPropertyDetailsbyEIDPortType)(this)).GetOwnerPropertyDetailsAsync(inValue);
        }
    }
}