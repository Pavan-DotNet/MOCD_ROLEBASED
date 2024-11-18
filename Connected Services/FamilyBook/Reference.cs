﻿//------------------------------------------------------------------------------
// <auto-generated>
//     This code was generated by a tool.
//     Runtime Version:4.0.30319.42000
//
//     Changes to this file may cause incorrect behavior and will be lost if
//     the code is regenerated.
// </auto-generated>
//------------------------------------------------------------------------------

namespace MOCDIntegrations.FamilyBook {
    
    
    /// <remarks/>
    [System.CodeDom.Compiler.GeneratedCodeAttribute("System.Xml", "4.8.3761.0")]
    [System.SerializableAttribute()]
    [System.Diagnostics.DebuggerStepThroughAttribute()]
    [System.ComponentModel.DesignerCategoryAttribute("code")]
    [System.Xml.Serialization.XmlTypeAttribute(AnonymousType=true, Namespace="http://xmlns.moi.gov.ae/2017/MOIServices/FamilyBookInquirySchema")]
    public partial class errorResponse : object, System.ComponentModel.INotifyPropertyChanged {
        
        private string codeField;
        
        private string typeField;
        
        private string arDescField;
        
        private string enDescField;
        
        private string refNumberField;
        
        /// <remarks/>
        [System.Xml.Serialization.XmlElementAttribute(Order=0)]
        public string code {
            get {
                return this.codeField;
            }
            set {
                this.codeField = value;
                this.RaisePropertyChanged("code");
            }
        }
        
        /// <remarks/>
        [System.Xml.Serialization.XmlElementAttribute(Order=1)]
        public string type {
            get {
                return this.typeField;
            }
            set {
                this.typeField = value;
                this.RaisePropertyChanged("type");
            }
        }
        
        /// <remarks/>
        [System.Xml.Serialization.XmlElementAttribute(Order=2)]
        public string arDesc {
            get {
                return this.arDescField;
            }
            set {
                this.arDescField = value;
                this.RaisePropertyChanged("arDesc");
            }
        }
        
        /// <remarks/>
        [System.Xml.Serialization.XmlElementAttribute(Order=3)]
        public string enDesc {
            get {
                return this.enDescField;
            }
            set {
                this.enDescField = value;
                this.RaisePropertyChanged("enDesc");
            }
        }
        
        /// <remarks/>
        [System.Xml.Serialization.XmlElementAttribute(Order=4)]
        public string refNumber {
            get {
                return this.refNumberField;
            }
            set {
                this.refNumberField = value;
                this.RaisePropertyChanged("refNumber");
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
    [System.Xml.Serialization.XmlIncludeAttribute(typeof(WifeType))]
    [System.Xml.Serialization.XmlIncludeAttribute(typeof(DependentType))]
    [System.CodeDom.Compiler.GeneratedCodeAttribute("System.Xml", "4.8.3761.0")]
    [System.SerializableAttribute()]
    [System.Diagnostics.DebuggerStepThroughAttribute()]
    [System.ComponentModel.DesignerCategoryAttribute("code")]
    [System.Xml.Serialization.XmlTypeAttribute(Namespace="http://xmlns.moi.gov.ae/2017/MOIServices/FamilyBookInquirySchema")]
    public partial class PersonDetailsType : object, System.ComponentModel.INotifyPropertyChanged {
        
        private string identityCardNumberField;
        
        private long unifiedNumberField;
        
        private string fullArabicNameField;
        
        private string fullEnglishNameField;
        
        private string clanNameArabicField;
        
        private string clanNameEnglishField;
        
        private LookupType genderField;
        
        private string motherNameArabicField;
        
        private string motherNameEnglishField;
        
        private System.DateTime dateOfBirthField;
        
        private LookupType countryOfBirthField;
        
        private LookupType emirateOfBirthField;
        
        private LookupType cityOfBirthField;
        
        private string placeOfBirthArField;
        
        private string placeOfBirthEnField;
        
        private LookupType maritalStatusField;
        
        private LookupType religionField;
        
        private LookupType nationalityField;
        
        private bool activeFlagField;
        
        /// <remarks/>
        [System.Xml.Serialization.XmlElementAttribute(Order=0)]
        public string identityCardNumber {
            get {
                return this.identityCardNumberField;
            }
            set {
                this.identityCardNumberField = value;
                this.RaisePropertyChanged("identityCardNumber");
            }
        }
        
        /// <remarks/>
        [System.Xml.Serialization.XmlElementAttribute(Order=1)]
        public long unifiedNumber {
            get {
                return this.unifiedNumberField;
            }
            set {
                this.unifiedNumberField = value;
                this.RaisePropertyChanged("unifiedNumber");
            }
        }
        
        /// <remarks/>
        [System.Xml.Serialization.XmlElementAttribute(Order=2)]
        public string fullArabicName {
            get {
                return this.fullArabicNameField;
            }
            set {
                this.fullArabicNameField = value;
                this.RaisePropertyChanged("fullArabicName");
            }
        }
        
        /// <remarks/>
        [System.Xml.Serialization.XmlElementAttribute(Order=3)]
        public string fullEnglishName {
            get {
                return this.fullEnglishNameField;
            }
            set {
                this.fullEnglishNameField = value;
                this.RaisePropertyChanged("fullEnglishName");
            }
        }
        
        /// <remarks/>
        [System.Xml.Serialization.XmlElementAttribute(Order=4)]
        public string clanNameArabic {
            get {
                return this.clanNameArabicField;
            }
            set {
                this.clanNameArabicField = value;
                this.RaisePropertyChanged("clanNameArabic");
            }
        }
        
        /// <remarks/>
        [System.Xml.Serialization.XmlElementAttribute(Order=5)]
        public string clanNameEnglish {
            get {
                return this.clanNameEnglishField;
            }
            set {
                this.clanNameEnglishField = value;
                this.RaisePropertyChanged("clanNameEnglish");
            }
        }
        
        /// <remarks/>
        [System.Xml.Serialization.XmlElementAttribute(Order=6)]
        public LookupType gender {
            get {
                return this.genderField;
            }
            set {
                this.genderField = value;
                this.RaisePropertyChanged("gender");
            }
        }
        
        /// <remarks/>
        [System.Xml.Serialization.XmlElementAttribute(Order=7)]
        public string motherNameArabic {
            get {
                return this.motherNameArabicField;
            }
            set {
                this.motherNameArabicField = value;
                this.RaisePropertyChanged("motherNameArabic");
            }
        }
        
        /// <remarks/>
        [System.Xml.Serialization.XmlElementAttribute(Order=8)]
        public string motherNameEnglish {
            get {
                return this.motherNameEnglishField;
            }
            set {
                this.motherNameEnglishField = value;
                this.RaisePropertyChanged("motherNameEnglish");
            }
        }
        
        /// <remarks/>
        [System.Xml.Serialization.XmlElementAttribute(Order=9)]
        public System.DateTime dateOfBirth {
            get {
                return this.dateOfBirthField;
            }
            set {
                this.dateOfBirthField = value;
                this.RaisePropertyChanged("dateOfBirth");
            }
        }
        
        /// <remarks/>
        [System.Xml.Serialization.XmlElementAttribute(Order=10)]
        public LookupType countryOfBirth {
            get {
                return this.countryOfBirthField;
            }
            set {
                this.countryOfBirthField = value;
                this.RaisePropertyChanged("countryOfBirth");
            }
        }
        
        /// <remarks/>
        [System.Xml.Serialization.XmlElementAttribute(Order=11)]
        public LookupType emirateOfBirth {
            get {
                return this.emirateOfBirthField;
            }
            set {
                this.emirateOfBirthField = value;
                this.RaisePropertyChanged("emirateOfBirth");
            }
        }
        
        /// <remarks/>
        [System.Xml.Serialization.XmlElementAttribute(Order=12)]
        public LookupType cityOfBirth {
            get {
                return this.cityOfBirthField;
            }
            set {
                this.cityOfBirthField = value;
                this.RaisePropertyChanged("cityOfBirth");
            }
        }
        
        /// <remarks/>
        [System.Xml.Serialization.XmlElementAttribute(Order=13)]
        public string placeOfBirthAr {
            get {
                return this.placeOfBirthArField;
            }
            set {
                this.placeOfBirthArField = value;
                this.RaisePropertyChanged("placeOfBirthAr");
            }
        }
        
        /// <remarks/>
        [System.Xml.Serialization.XmlElementAttribute(Order=14)]
        public string placeOfBirthEn {
            get {
                return this.placeOfBirthEnField;
            }
            set {
                this.placeOfBirthEnField = value;
                this.RaisePropertyChanged("placeOfBirthEn");
            }
        }
        
        /// <remarks/>
        [System.Xml.Serialization.XmlElementAttribute(Order=15)]
        public LookupType maritalStatus {
            get {
                return this.maritalStatusField;
            }
            set {
                this.maritalStatusField = value;
                this.RaisePropertyChanged("maritalStatus");
            }
        }
        
        /// <remarks/>
        [System.Xml.Serialization.XmlElementAttribute(Order=16)]
        public LookupType religion {
            get {
                return this.religionField;
            }
            set {
                this.religionField = value;
                this.RaisePropertyChanged("religion");
            }
        }
        
        /// <remarks/>
        [System.Xml.Serialization.XmlElementAttribute(Order=17)]
        public LookupType nationality {
            get {
                return this.nationalityField;
            }
            set {
                this.nationalityField = value;
                this.RaisePropertyChanged("nationality");
            }
        }
        
        /// <remarks/>
        [System.Xml.Serialization.XmlElementAttribute(Order=18)]
        public bool activeFlag {
            get {
                return this.activeFlagField;
            }
            set {
                this.activeFlagField = value;
                this.RaisePropertyChanged("activeFlag");
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
    [System.Xml.Serialization.XmlTypeAttribute(Namespace="http://xmlns.moi.gov.ae/2017/MOIServices/FamilyBookInquirySchema")]
    public partial class LookupType : object, System.ComponentModel.INotifyPropertyChanged {
        
        private long idField;
        
        private string arDescField;
        
        private string enDescField;
        
        /// <remarks/>
        [System.Xml.Serialization.XmlElementAttribute(Order=0)]
        public long id {
            get {
                return this.idField;
            }
            set {
                this.idField = value;
                this.RaisePropertyChanged("id");
            }
        }
        
        /// <remarks/>
        [System.Xml.Serialization.XmlElementAttribute(Order=1)]
        public string arDesc {
            get {
                return this.arDescField;
            }
            set {
                this.arDescField = value;
                this.RaisePropertyChanged("arDesc");
            }
        }
        
        /// <remarks/>
        [System.Xml.Serialization.XmlElementAttribute(Order=2)]
        public string enDesc {
            get {
                return this.enDescField;
            }
            set {
                this.enDescField = value;
                this.RaisePropertyChanged("enDesc");
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
    [System.Xml.Serialization.XmlTypeAttribute(Namespace="http://xmlns.moi.gov.ae/2017/MOIServices/FamilyBookInquirySchema")]
    public partial class WifeType : PersonDetailsType {
        
        private System.DateTime marriageDateField;
        
        private bool marriageDateFieldSpecified;
        
        /// <remarks/>
        [System.Xml.Serialization.XmlElementAttribute(Order=0)]
        public System.DateTime marriageDate {
            get {
                return this.marriageDateField;
            }
            set {
                this.marriageDateField = value;
                this.RaisePropertyChanged("marriageDate");
            }
        }
        
        /// <remarks/>
        [System.Xml.Serialization.XmlIgnoreAttribute()]
        public bool marriageDateSpecified {
            get {
                return this.marriageDateFieldSpecified;
            }
            set {
                this.marriageDateFieldSpecified = value;
                this.RaisePropertyChanged("marriageDateSpecified");
            }
        }
    }
    
    /// <remarks/>
    [System.CodeDom.Compiler.GeneratedCodeAttribute("System.Xml", "4.8.3761.0")]
    [System.SerializableAttribute()]
    [System.Diagnostics.DebuggerStepThroughAttribute()]
    [System.ComponentModel.DesignerCategoryAttribute("code")]
    [System.Xml.Serialization.XmlTypeAttribute(Namespace="http://xmlns.moi.gov.ae/2017/MOIServices/FamilyBookInquirySchema")]
    public partial class DependentType : PersonDetailsType {
        
        private LookupType relationshipToFamilyField;
        
        private string motherIdentityCardNumberField;
        
        /// <remarks/>
        [System.Xml.Serialization.XmlElementAttribute(Order=0)]
        public LookupType relationshipToFamily {
            get {
                return this.relationshipToFamilyField;
            }
            set {
                this.relationshipToFamilyField = value;
                this.RaisePropertyChanged("relationshipToFamily");
            }
        }
        
        /// <remarks/>
        [System.Xml.Serialization.XmlElementAttribute(Order=1)]
        public string motherIdentityCardNumber {
            get {
                return this.motherIdentityCardNumberField;
            }
            set {
                this.motherIdentityCardNumberField = value;
                this.RaisePropertyChanged("motherIdentityCardNumber");
            }
        }
    }
    
    /// <remarks/>
    [System.CodeDom.Compiler.GeneratedCodeAttribute("System.Xml", "4.8.3761.0")]
    [System.SerializableAttribute()]
    [System.Diagnostics.DebuggerStepThroughAttribute()]
    [System.ComponentModel.DesignerCategoryAttribute("code")]
    [System.Xml.Serialization.XmlTypeAttribute(Namespace="http://xmlns.moi.gov.ae/2017/MOIServices/FamilyBookInquirySchema")]
    public partial class FamilyBookDetailsResponseType : object, System.ComponentModel.INotifyPropertyChanged {
        
        private string familybookSequenceField;
        
        private System.Nullable<System.DateTime> familybookIssueDateField;
        
        private bool familybookIssueDateFieldSpecified;
        
        private string familySequenceField;
        
        private LookupType cityField;
        
        private int childrenCountField;
        
        private int wivesCountField;
        
        private PersonDetailsType familyHeadField;
        
        private DependentType[] dependentsField;
        
        private WifeType[] wivesField;
        
        /// <remarks/>
        [System.Xml.Serialization.XmlElementAttribute(DataType="integer", IsNullable=true, Order=0)]
        public string familybookSequence {
            get {
                return this.familybookSequenceField;
            }
            set {
                this.familybookSequenceField = value;
                this.RaisePropertyChanged("familybookSequence");
            }
        }
        
        /// <remarks/>
        [System.Xml.Serialization.XmlElementAttribute(IsNullable=true, Order=1)]
        public System.Nullable<System.DateTime> familybookIssueDate {
            get {
                return this.familybookIssueDateField;
            }
            set {
                this.familybookIssueDateField = value;
                this.RaisePropertyChanged("familybookIssueDate");
            }
        }
        
        /// <remarks/>
        [System.Xml.Serialization.XmlIgnoreAttribute()]
        public bool familybookIssueDateSpecified {
            get {
                return this.familybookIssueDateFieldSpecified;
            }
            set {
                this.familybookIssueDateFieldSpecified = value;
                this.RaisePropertyChanged("familybookIssueDateSpecified");
            }
        }
        
        /// <remarks/>
        [System.Xml.Serialization.XmlElementAttribute(DataType="integer", Order=2)]
        public string familySequence {
            get {
                return this.familySequenceField;
            }
            set {
                this.familySequenceField = value;
                this.RaisePropertyChanged("familySequence");
            }
        }
        
        /// <remarks/>
        [System.Xml.Serialization.XmlElementAttribute(Order=3)]
        public LookupType city {
            get {
                return this.cityField;
            }
            set {
                this.cityField = value;
                this.RaisePropertyChanged("city");
            }
        }
        
        /// <remarks/>
        [System.Xml.Serialization.XmlElementAttribute(Order=4)]
        public int childrenCount {
            get {
                return this.childrenCountField;
            }
            set {
                this.childrenCountField = value;
                this.RaisePropertyChanged("childrenCount");
            }
        }
        
        /// <remarks/>
        [System.Xml.Serialization.XmlElementAttribute(Order=5)]
        public int wivesCount {
            get {
                return this.wivesCountField;
            }
            set {
                this.wivesCountField = value;
                this.RaisePropertyChanged("wivesCount");
            }
        }
        
        /// <remarks/>
        [System.Xml.Serialization.XmlElementAttribute(Order=6)]
        public PersonDetailsType familyHead {
            get {
                return this.familyHeadField;
            }
            set {
                this.familyHeadField = value;
                this.RaisePropertyChanged("familyHead");
            }
        }
        
        /// <remarks/>
        [System.Xml.Serialization.XmlArrayAttribute(Order=7)]
        [System.Xml.Serialization.XmlArrayItemAttribute("dependent", IsNullable=false)]
        public DependentType[] dependents {
            get {
                return this.dependentsField;
            }
            set {
                this.dependentsField = value;
                this.RaisePropertyChanged("dependents");
            }
        }
        
        /// <remarks/>
        [System.Xml.Serialization.XmlArrayAttribute(Order=8)]
        [System.Xml.Serialization.XmlArrayItemAttribute("wife", IsNullable=false)]
        public WifeType[] wives {
            get {
                return this.wivesField;
            }
            set {
                this.wivesField = value;
                this.RaisePropertyChanged("wives");
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
    [System.Xml.Serialization.XmlTypeAttribute(Namespace="http://xmlns.moi.gov.ae/2017/MOIServices/FamilyBookInquirySchema")]
    public partial class FamilyBookRequestType : object, System.ComponentModel.INotifyPropertyChanged {
        
        private object[] itemsField;
        
        private ItemsChoiceType[] itemsElementNameField;
        
        /// <remarks/>
        [System.Xml.Serialization.XmlElementAttribute("cityId", typeof(int), Order=0)]
        [System.Xml.Serialization.XmlElementAttribute("familySequence", typeof(string), DataType="integer", Order=0)]
        [System.Xml.Serialization.XmlElementAttribute("identityCardNumber", typeof(string), Order=0)]
        [System.Xml.Serialization.XmlElementAttribute("unifiedNumber", typeof(long), Order=0)]
        [System.Xml.Serialization.XmlChoiceIdentifierAttribute("ItemsElementName")]
        public object[] Items {
            get {
                return this.itemsField;
            }
            set {
                this.itemsField = value;
                this.RaisePropertyChanged("Items");
            }
        }
        
        /// <remarks/>
        [System.Xml.Serialization.XmlElementAttribute("ItemsElementName", Order=1)]
        [System.Xml.Serialization.XmlIgnoreAttribute()]
        public ItemsChoiceType[] ItemsElementName {
            get {
                return this.itemsElementNameField;
            }
            set {
                this.itemsElementNameField = value;
                this.RaisePropertyChanged("ItemsElementName");
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
    [System.Xml.Serialization.XmlTypeAttribute(Namespace="http://xmlns.moi.gov.ae/2017/MOIServices/FamilyBookInquirySchema", IncludeInSchema=false)]
    public enum ItemsChoiceType {
        
        /// <remarks/>
        cityId,
        
        /// <remarks/>
        familySequence,
        
        /// <remarks/>
        identityCardNumber,
        
        /// <remarks/>
        unifiedNumber,
    }
    
    [System.CodeDom.Compiler.GeneratedCodeAttribute("System.ServiceModel", "4.0.0.0")]
    [System.ServiceModel.ServiceContractAttribute(Namespace="http://xmlns.moi.gov.ae/2017/MOIServices/FamilyBookInquiry", ConfigurationName="FamilyBook.getFamilyBookDetails_ptt")]
    public interface getFamilyBookDetails_ptt {
        
        // CODEGEN: Generating message contract since the operation getFamilyBookDetails is neither RPC nor document wrapped.
        [System.ServiceModel.OperationContractAttribute(Action="getFamilyBookDetails", ReplyAction="*")]
        [System.ServiceModel.FaultContractAttribute(typeof(MOCDIntegrations.FamilyBook.errorResponse), Action="getFamilyBookDetails", Name="errorResponse", Namespace="http://xmlns.moi.gov.ae/2017/MOIServices/FamilyBookInquirySchema")]
        [System.ServiceModel.XmlSerializerFormatAttribute(SupportFaults=true)]
        MOCDIntegrations.FamilyBook.getFamilyBookDetailsResponse getFamilyBookDetails(MOCDIntegrations.FamilyBook.getFamilyBookDetailsRequest request);
        
        [System.ServiceModel.OperationContractAttribute(Action="getFamilyBookDetails", ReplyAction="*")]
        System.Threading.Tasks.Task<MOCDIntegrations.FamilyBook.getFamilyBookDetailsResponse> getFamilyBookDetailsAsync(MOCDIntegrations.FamilyBook.getFamilyBookDetailsRequest request);
    }
    
    /// <remarks/>
    [System.CodeDom.Compiler.GeneratedCodeAttribute("System.Xml", "4.8.3761.0")]
    [System.SerializableAttribute()]
    [System.Diagnostics.DebuggerStepThroughAttribute()]
    [System.ComponentModel.DesignerCategoryAttribute("code")]
    [System.Xml.Serialization.XmlTypeAttribute(Namespace="http://xmlns.moi.gov.ae/2017/MOIServices/FamilyBookInquirySchema")]
    public partial class TrnHeaderType : object, System.ComponentModel.INotifyPropertyChanged {
        
        private string transactionIdField;
        
        private string serviceProviderEntityField;
        
        /// <remarks/>
        [System.Xml.Serialization.XmlElementAttribute(Order=0)]
        public string transactionId {
            get {
                return this.transactionIdField;
            }
            set {
                this.transactionIdField = value;
                this.RaisePropertyChanged("transactionId");
            }
        }
        
        /// <remarks/>
        [System.Xml.Serialization.XmlElementAttribute(Order=1)]
        public string serviceProviderEntity {
            get {
                return this.serviceProviderEntityField;
            }
            set {
                this.serviceProviderEntityField = value;
                this.RaisePropertyChanged("serviceProviderEntity");
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
    public partial class getFamilyBookDetailsRequest {
        
        [System.ServiceModel.MessageHeaderAttribute(Namespace="http://xmlns.moi.gov.ae/2017/MOIServices/FamilyBookInquirySchema")]
        public MOCDIntegrations.FamilyBook.TrnHeaderType TrnHeader;
        
        [System.ServiceModel.MessageBodyMemberAttribute(Namespace="http://xmlns.moi.gov.ae/2017/MOIServices/FamilyBookInquirySchema", Order=0)]
        public MOCDIntegrations.FamilyBook.FamilyBookRequestType familyBookRequest;
        
        public getFamilyBookDetailsRequest() {
        }
        
        public getFamilyBookDetailsRequest(MOCDIntegrations.FamilyBook.TrnHeaderType TrnHeader, MOCDIntegrations.FamilyBook.FamilyBookRequestType familyBookRequest) {
            this.TrnHeader = TrnHeader;
            this.familyBookRequest = familyBookRequest;
        }
    }
    
    [System.Diagnostics.DebuggerStepThroughAttribute()]
    [System.CodeDom.Compiler.GeneratedCodeAttribute("System.ServiceModel", "4.0.0.0")]
    [System.ComponentModel.EditorBrowsableAttribute(System.ComponentModel.EditorBrowsableState.Advanced)]
    [System.ServiceModel.MessageContractAttribute(IsWrapped=false)]
    public partial class getFamilyBookDetailsResponse {
        
        [System.ServiceModel.MessageHeaderAttribute(Namespace="http://xmlns.moi.gov.ae/2017/MOIServices/FamilyBookInquirySchema")]
        public MOCDIntegrations.FamilyBook.TrnHeaderType TrnHeader;
        
        [System.ServiceModel.MessageBodyMemberAttribute(Namespace="http://xmlns.moi.gov.ae/2017/MOIServices/FamilyBookInquirySchema", Order=0)]
        public MOCDIntegrations.FamilyBook.FamilyBookDetailsResponseType familyBookDetailsResponse;
        
        public getFamilyBookDetailsResponse() {
        }
        
        public getFamilyBookDetailsResponse(MOCDIntegrations.FamilyBook.TrnHeaderType TrnHeader, MOCDIntegrations.FamilyBook.FamilyBookDetailsResponseType familyBookDetailsResponse) {
            this.TrnHeader = TrnHeader;
            this.familyBookDetailsResponse = familyBookDetailsResponse;
        }
    }
    
    [System.CodeDom.Compiler.GeneratedCodeAttribute("System.ServiceModel", "4.0.0.0")]
    public interface getFamilyBookDetails_pttChannel : MOCDIntegrations.FamilyBook.getFamilyBookDetails_ptt, System.ServiceModel.IClientChannel {
    }
    
    [System.Diagnostics.DebuggerStepThroughAttribute()]
    [System.CodeDom.Compiler.GeneratedCodeAttribute("System.ServiceModel", "4.0.0.0")]
    public partial class getFamilyBookDetails_pttClient : System.ServiceModel.ClientBase<MOCDIntegrations.FamilyBook.getFamilyBookDetails_ptt>, MOCDIntegrations.FamilyBook.getFamilyBookDetails_ptt {
        
        public getFamilyBookDetails_pttClient() {
        }
        
        public getFamilyBookDetails_pttClient(string endpointConfigurationName) : 
                base(endpointConfigurationName) {
        }
        
        public getFamilyBookDetails_pttClient(string endpointConfigurationName, string remoteAddress) : 
                base(endpointConfigurationName, remoteAddress) {
        }
        
        public getFamilyBookDetails_pttClient(string endpointConfigurationName, System.ServiceModel.EndpointAddress remoteAddress) : 
                base(endpointConfigurationName, remoteAddress) {
        }
        
        public getFamilyBookDetails_pttClient(System.ServiceModel.Channels.Binding binding, System.ServiceModel.EndpointAddress remoteAddress) : 
                base(binding, remoteAddress) {
        }
        
        [System.ComponentModel.EditorBrowsableAttribute(System.ComponentModel.EditorBrowsableState.Advanced)]
        MOCDIntegrations.FamilyBook.getFamilyBookDetailsResponse MOCDIntegrations.FamilyBook.getFamilyBookDetails_ptt.getFamilyBookDetails(MOCDIntegrations.FamilyBook.getFamilyBookDetailsRequest request) {
            return base.Channel.getFamilyBookDetails(request);
        }
        
        public MOCDIntegrations.FamilyBook.FamilyBookDetailsResponseType getFamilyBookDetails(ref MOCDIntegrations.FamilyBook.TrnHeaderType TrnHeader, MOCDIntegrations.FamilyBook.FamilyBookRequestType familyBookRequest) {
            MOCDIntegrations.FamilyBook.getFamilyBookDetailsRequest inValue = new MOCDIntegrations.FamilyBook.getFamilyBookDetailsRequest();
            inValue.TrnHeader = TrnHeader;
            inValue.familyBookRequest = familyBookRequest;
            MOCDIntegrations.FamilyBook.getFamilyBookDetailsResponse retVal = ((MOCDIntegrations.FamilyBook.getFamilyBookDetails_ptt)(this)).getFamilyBookDetails(inValue);
            TrnHeader = retVal.TrnHeader;
            return retVal.familyBookDetailsResponse;
        }
        
        [System.ComponentModel.EditorBrowsableAttribute(System.ComponentModel.EditorBrowsableState.Advanced)]
        System.Threading.Tasks.Task<MOCDIntegrations.FamilyBook.getFamilyBookDetailsResponse> MOCDIntegrations.FamilyBook.getFamilyBookDetails_ptt.getFamilyBookDetailsAsync(MOCDIntegrations.FamilyBook.getFamilyBookDetailsRequest request) {
            return base.Channel.getFamilyBookDetailsAsync(request);
        }
        
        public System.Threading.Tasks.Task<MOCDIntegrations.FamilyBook.getFamilyBookDetailsResponse> getFamilyBookDetailsAsync(MOCDIntegrations.FamilyBook.TrnHeaderType TrnHeader, MOCDIntegrations.FamilyBook.FamilyBookRequestType familyBookRequest) {
            MOCDIntegrations.FamilyBook.getFamilyBookDetailsRequest inValue = new MOCDIntegrations.FamilyBook.getFamilyBookDetailsRequest();
            inValue.TrnHeader = TrnHeader;
            inValue.familyBookRequest = familyBookRequest;
            return ((MOCDIntegrations.FamilyBook.getFamilyBookDetails_ptt)(this)).getFamilyBookDetailsAsync(inValue);
        }
    }
}