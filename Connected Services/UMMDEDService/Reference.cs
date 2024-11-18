﻿//------------------------------------------------------------------------------
// <auto-generated>
//     This code was generated by a tool.
//     Runtime Version:4.0.30319.42000
//
//     Changes to this file may cause incorrect behavior and will be lost if
//     the code is regenerated.
// </auto-generated>
//------------------------------------------------------------------------------

namespace MOCDIntegrations.UMMDEDService {
    
    
    [System.CodeDom.Compiler.GeneratedCodeAttribute("System.ServiceModel", "4.0.0.0")]
    [System.ServiceModel.ServiceContractAttribute(Namespace="http://www.informatica.com/dis/ws/", ConfigurationName="UMMDEDService.UMM_DED_getLicenseDetailsbyEIDPortType")]
    public interface UMM_DED_getLicenseDetailsbyEIDPortType {
        
        // CODEGEN: Generating message contract since the operation LicenseDetails is neither RPC nor document wrapped.
        [System.ServiceModel.OperationContractAttribute(Action="", ReplyAction="*")]
        [System.ServiceModel.XmlSerializerFormatAttribute(SupportFaults=true)]
        MOCDIntegrations.UMMDEDService.LicenseDetails_Output LicenseDetails(MOCDIntegrations.UMMDEDService.LicenseDetails_Input request);
        
        [System.ServiceModel.OperationContractAttribute(Action="", ReplyAction="*")]
        System.Threading.Tasks.Task<MOCDIntegrations.UMMDEDService.LicenseDetails_Output> LicenseDetailsAsync(MOCDIntegrations.UMMDEDService.LicenseDetails_Input request);
    }
    
    /// <remarks/>
    [System.CodeDom.Compiler.GeneratedCodeAttribute("System.Xml", "4.8.3761.0")]
    [System.SerializableAttribute()]
    [System.Diagnostics.DebuggerStepThroughAttribute()]
    [System.ComponentModel.DesignerCategoryAttribute("code")]
    [System.Xml.Serialization.XmlTypeAttribute(AnonymousType=true, Namespace="http://www.informatica.com/dis/ws/")]
    public partial class LicenseDetails : object, System.ComponentModel.INotifyPropertyChanged {
        
        private string emiratesIDField;
        
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
        
        public event System.ComponentModel.PropertyChangedEventHandler PropertyChanged;
        
        protected void RaisePropertyChanged(string propertyName) {
            System.ComponentModel.PropertyChangedEventHandler propertyChanged = this.PropertyChanged;
            if ((propertyChanged != null)) {
                propertyChanged(this, new System.ComponentModel.PropertyChangedEventArgs(propertyName));
            }
        }
    }
    
    /// <remarks/>
    [System.CodeDom.Compiler.GeneratedCodeAttribute("System.Xml", "4.8.3761.0")]
    [System.SerializableAttribute()]
    [System.Diagnostics.DebuggerStepThroughAttribute()]
    [System.ComponentModel.DesignerCategoryAttribute("code")]
    [System.Xml.Serialization.XmlTypeAttribute(AnonymousType=true, Namespace="http://www.informatica.com/dis/ws/")]
    public partial class LicenseDetailsResponse : object, System.ComponentModel.INotifyPropertyChanged {
        
        private LicenseDetailsResponseLicenseDetails[] licenseDetailsField;
        
        private LicenseDetailsResponseError[] errorField;
        
        /// <remarks/>
        [System.Xml.Serialization.XmlElementAttribute("LicenseDetails", Order=0)]
        public LicenseDetailsResponseLicenseDetails[] LicenseDetails {
            get {
                return this.licenseDetailsField;
            }
            set {
                this.licenseDetailsField = value;
                this.RaisePropertyChanged("LicenseDetails");
            }
        }
        
        /// <remarks/>
        [System.Xml.Serialization.XmlElementAttribute("Error", Order=1)]
        public LicenseDetailsResponseError[] Error {
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
    [System.CodeDom.Compiler.GeneratedCodeAttribute("System.Xml", "4.8.3761.0")]
    [System.SerializableAttribute()]
    [System.Diagnostics.DebuggerStepThroughAttribute()]
    [System.ComponentModel.DesignerCategoryAttribute("code")]
    [System.Xml.Serialization.XmlTypeAttribute(AnonymousType=true, Namespace="http://www.informatica.com/dis/ws/")]
    public partial class LicenseDetailsResponseLicenseDetails : object, System.ComponentModel.INotifyPropertyChanged {
        
        private string businessLicenseIDField;
        
        private string businessNameARField;
        
        private string businessNameENField;
        
        private string establishmentDateField;
        
        private string expiryDateField;
        
        private LicenseDetailsResponseLicenseDetailsOwnerDetails[] ownerDetailsField;
        
        private LicenseDetailsResponseLicenseDetailsBusinessActivity[] businessActivityField;
        
        /// <remarks/>
        [System.Xml.Serialization.XmlElementAttribute(Order=0)]
        public string BusinessLicenseID {
            get {
                return this.businessLicenseIDField;
            }
            set {
                this.businessLicenseIDField = value;
                this.RaisePropertyChanged("BusinessLicenseID");
            }
        }
        
        /// <remarks/>
        [System.Xml.Serialization.XmlElementAttribute(Order=1)]
        public string BusinessNameAR {
            get {
                return this.businessNameARField;
            }
            set {
                this.businessNameARField = value;
                this.RaisePropertyChanged("BusinessNameAR");
            }
        }
        
        /// <remarks/>
        [System.Xml.Serialization.XmlElementAttribute(Order=2)]
        public string BusinessNameEN {
            get {
                return this.businessNameENField;
            }
            set {
                this.businessNameENField = value;
                this.RaisePropertyChanged("BusinessNameEN");
            }
        }
        
        /// <remarks/>
        [System.Xml.Serialization.XmlElementAttribute(Order=3)]
        public string EstablishmentDate {
            get {
                return this.establishmentDateField;
            }
            set {
                this.establishmentDateField = value;
                this.RaisePropertyChanged("EstablishmentDate");
            }
        }
        
        /// <remarks/>
        [System.Xml.Serialization.XmlElementAttribute(Order=4)]
        public string ExpiryDate {
            get {
                return this.expiryDateField;
            }
            set {
                this.expiryDateField = value;
                this.RaisePropertyChanged("ExpiryDate");
            }
        }
        
        /// <remarks/>
        [System.Xml.Serialization.XmlElementAttribute("OwnerDetails", Order=5)]
        public LicenseDetailsResponseLicenseDetailsOwnerDetails[] OwnerDetails {
            get {
                return this.ownerDetailsField;
            }
            set {
                this.ownerDetailsField = value;
                this.RaisePropertyChanged("OwnerDetails");
            }
        }
        
        /// <remarks/>
        [System.Xml.Serialization.XmlElementAttribute("BusinessActivity", Order=6)]
        public LicenseDetailsResponseLicenseDetailsBusinessActivity[] BusinessActivity {
            get {
                return this.businessActivityField;
            }
            set {
                this.businessActivityField = value;
                this.RaisePropertyChanged("BusinessActivity");
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
    [System.CodeDom.Compiler.GeneratedCodeAttribute("System.Xml", "4.8.3761.0")]
    [System.SerializableAttribute()]
    [System.Diagnostics.DebuggerStepThroughAttribute()]
    [System.ComponentModel.DesignerCategoryAttribute("code")]
    [System.Xml.Serialization.XmlTypeAttribute(AnonymousType=true, Namespace="http://www.informatica.com/dis/ws/")]
    public partial class LicenseDetailsResponseLicenseDetailsOwnerDetails : object, System.ComponentModel.INotifyPropertyChanged {
        
        private string ownerEmirateIDField;
        
        private string ownerFulNameARField;
        
        private string ownerFulNameENField;
        
        private string ownerRoleARField;
        
        private string ownerRoleENField;
        
        private string ownershipPercentageField;
        
        /// <remarks/>
        [System.Xml.Serialization.XmlElementAttribute(Order=0)]
        public string OwnerEmirateID {
            get {
                return this.ownerEmirateIDField;
            }
            set {
                this.ownerEmirateIDField = value;
                this.RaisePropertyChanged("OwnerEmirateID");
            }
        }
        
        /// <remarks/>
        [System.Xml.Serialization.XmlElementAttribute(Order=1)]
        public string OwnerFulNameAR {
            get {
                return this.ownerFulNameARField;
            }
            set {
                this.ownerFulNameARField = value;
                this.RaisePropertyChanged("OwnerFulNameAR");
            }
        }
        
        /// <remarks/>
        [System.Xml.Serialization.XmlElementAttribute(Order=2)]
        public string OwnerFulNameEN {
            get {
                return this.ownerFulNameENField;
            }
            set {
                this.ownerFulNameENField = value;
                this.RaisePropertyChanged("OwnerFulNameEN");
            }
        }
        
        /// <remarks/>
        [System.Xml.Serialization.XmlElementAttribute(Order=3)]
        public string OwnerRoleAR {
            get {
                return this.ownerRoleARField;
            }
            set {
                this.ownerRoleARField = value;
                this.RaisePropertyChanged("OwnerRoleAR");
            }
        }
        
        /// <remarks/>
        [System.Xml.Serialization.XmlElementAttribute(Order=4)]
        public string OwnerRoleEN {
            get {
                return this.ownerRoleENField;
            }
            set {
                this.ownerRoleENField = value;
                this.RaisePropertyChanged("OwnerRoleEN");
            }
        }
        
        /// <remarks/>
        [System.Xml.Serialization.XmlElementAttribute(Order=5)]
        public string OwnershipPercentage {
            get {
                return this.ownershipPercentageField;
            }
            set {
                this.ownershipPercentageField = value;
                this.RaisePropertyChanged("OwnershipPercentage");
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
    [System.CodeDom.Compiler.GeneratedCodeAttribute("System.Xml", "4.8.3761.0")]
    [System.SerializableAttribute()]
    [System.Diagnostics.DebuggerStepThroughAttribute()]
    [System.ComponentModel.DesignerCategoryAttribute("code")]
    [System.Xml.Serialization.XmlTypeAttribute(AnonymousType=true, Namespace="http://www.informatica.com/dis/ws/")]
    public partial class LicenseDetailsResponseLicenseDetailsBusinessActivity : object, System.ComponentModel.INotifyPropertyChanged {
        
        private string businessActivityCodeField;
        
        private string businessActivityDescENField;
        
        private string businessActivityDescARField;
        
        /// <remarks/>
        [System.Xml.Serialization.XmlElementAttribute(Order=0)]
        public string BusinessActivityCode {
            get {
                return this.businessActivityCodeField;
            }
            set {
                this.businessActivityCodeField = value;
                this.RaisePropertyChanged("BusinessActivityCode");
            }
        }
        
        /// <remarks/>
        [System.Xml.Serialization.XmlElementAttribute(Order=1)]
        public string BusinessActivityDescEN {
            get {
                return this.businessActivityDescENField;
            }
            set {
                this.businessActivityDescENField = value;
                this.RaisePropertyChanged("BusinessActivityDescEN");
            }
        }
        
        /// <remarks/>
        [System.Xml.Serialization.XmlElementAttribute(Order=2)]
        public string BusinessActivityDescAR {
            get {
                return this.businessActivityDescARField;
            }
            set {
                this.businessActivityDescARField = value;
                this.RaisePropertyChanged("BusinessActivityDescAR");
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
    [System.CodeDom.Compiler.GeneratedCodeAttribute("System.Xml", "4.8.3761.0")]
    [System.SerializableAttribute()]
    [System.Diagnostics.DebuggerStepThroughAttribute()]
    [System.ComponentModel.DesignerCategoryAttribute("code")]
    [System.Xml.Serialization.XmlTypeAttribute(AnonymousType=true, Namespace="http://www.informatica.com/dis/ws/")]
    public partial class LicenseDetailsResponseError : object, System.ComponentModel.INotifyPropertyChanged {
        
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
    public partial class LicenseDetails_Input {
        
        [System.ServiceModel.MessageBodyMemberAttribute(Namespace="http://www.informatica.com/dis/ws/", Order=0)]
        public MOCDIntegrations.UMMDEDService.LicenseDetails LicenseDetails;
        
        public LicenseDetails_Input() {
        }
        
        public LicenseDetails_Input(MOCDIntegrations.UMMDEDService.LicenseDetails LicenseDetails) {
            this.LicenseDetails = LicenseDetails;
        }
    }
    
    [System.Diagnostics.DebuggerStepThroughAttribute()]
    [System.CodeDom.Compiler.GeneratedCodeAttribute("System.ServiceModel", "4.0.0.0")]
    [System.ComponentModel.EditorBrowsableAttribute(System.ComponentModel.EditorBrowsableState.Advanced)]
    [System.ServiceModel.MessageContractAttribute(IsWrapped=false)]
    public partial class LicenseDetails_Output {
        
        [System.ServiceModel.MessageBodyMemberAttribute(Namespace="http://www.informatica.com/dis/ws/", Order=0)]
        public MOCDIntegrations.UMMDEDService.LicenseDetailsResponse LicenseDetailsResponse;
        
        public LicenseDetails_Output() {
        }
        
        public LicenseDetails_Output(MOCDIntegrations.UMMDEDService.LicenseDetailsResponse LicenseDetailsResponse) {
            this.LicenseDetailsResponse = LicenseDetailsResponse;
        }
    }
    
    [System.CodeDom.Compiler.GeneratedCodeAttribute("System.ServiceModel", "4.0.0.0")]
    public interface UMM_DED_getLicenseDetailsbyEIDPortTypeChannel : MOCDIntegrations.UMMDEDService.UMM_DED_getLicenseDetailsbyEIDPortType, System.ServiceModel.IClientChannel {
    }
    
    [System.Diagnostics.DebuggerStepThroughAttribute()]
    [System.CodeDom.Compiler.GeneratedCodeAttribute("System.ServiceModel", "4.0.0.0")]
    public partial class UMM_DED_getLicenseDetailsbyEIDPortTypeClient : System.ServiceModel.ClientBase<MOCDIntegrations.UMMDEDService.UMM_DED_getLicenseDetailsbyEIDPortType>, MOCDIntegrations.UMMDEDService.UMM_DED_getLicenseDetailsbyEIDPortType {
        
        public UMM_DED_getLicenseDetailsbyEIDPortTypeClient() {
        }
        
        public UMM_DED_getLicenseDetailsbyEIDPortTypeClient(string endpointConfigurationName) : 
                base(endpointConfigurationName) {
        }
        
        public UMM_DED_getLicenseDetailsbyEIDPortTypeClient(string endpointConfigurationName, string remoteAddress) : 
                base(endpointConfigurationName, remoteAddress) {
        }
        
        public UMM_DED_getLicenseDetailsbyEIDPortTypeClient(string endpointConfigurationName, System.ServiceModel.EndpointAddress remoteAddress) : 
                base(endpointConfigurationName, remoteAddress) {
        }
        
        public UMM_DED_getLicenseDetailsbyEIDPortTypeClient(System.ServiceModel.Channels.Binding binding, System.ServiceModel.EndpointAddress remoteAddress) : 
                base(binding, remoteAddress) {
        }
        
        [System.ComponentModel.EditorBrowsableAttribute(System.ComponentModel.EditorBrowsableState.Advanced)]
        MOCDIntegrations.UMMDEDService.LicenseDetails_Output MOCDIntegrations.UMMDEDService.UMM_DED_getLicenseDetailsbyEIDPortType.LicenseDetails(MOCDIntegrations.UMMDEDService.LicenseDetails_Input request) {
            return base.Channel.LicenseDetails(request);
        }
        
        public MOCDIntegrations.UMMDEDService.LicenseDetailsResponse LicenseDetails(MOCDIntegrations.UMMDEDService.LicenseDetails LicenseDetails1) {
            MOCDIntegrations.UMMDEDService.LicenseDetails_Input inValue = new MOCDIntegrations.UMMDEDService.LicenseDetails_Input();
            inValue.LicenseDetails = LicenseDetails1;
            MOCDIntegrations.UMMDEDService.LicenseDetails_Output retVal = ((MOCDIntegrations.UMMDEDService.UMM_DED_getLicenseDetailsbyEIDPortType)(this)).LicenseDetails(inValue);
            return retVal.LicenseDetailsResponse;
        }
        
        [System.ComponentModel.EditorBrowsableAttribute(System.ComponentModel.EditorBrowsableState.Advanced)]
        System.Threading.Tasks.Task<MOCDIntegrations.UMMDEDService.LicenseDetails_Output> MOCDIntegrations.UMMDEDService.UMM_DED_getLicenseDetailsbyEIDPortType.LicenseDetailsAsync(MOCDIntegrations.UMMDEDService.LicenseDetails_Input request) {
            return base.Channel.LicenseDetailsAsync(request);
        }
        
        public System.Threading.Tasks.Task<MOCDIntegrations.UMMDEDService.LicenseDetails_Output> LicenseDetailsAsync(MOCDIntegrations.UMMDEDService.LicenseDetails LicenseDetails) {
            MOCDIntegrations.UMMDEDService.LicenseDetails_Input inValue = new MOCDIntegrations.UMMDEDService.LicenseDetails_Input();
            inValue.LicenseDetails = LicenseDetails;
            return ((MOCDIntegrations.UMMDEDService.UMM_DED_getLicenseDetailsbyEIDPortType)(this)).LicenseDetailsAsync(inValue);
        }
    }
}