require 'rails_helper'

RSpec.describe 'Authorization boundaries', type: :request do
  let(:patient) { create(:user, :patient) }
  let(:physician) { create(:user, :physician) }
  let(:outsider_patient) { create(:user, :patient) }
  let(:outsider_physician) { create(:user, :physician) }

  def auth_header(user)
    token = JWT.encode({ user_id: user.id }, Rails.application.secret_key_base, 'HS256')
    { 'Authorization' => "Bearer #{token}" }
  end

  describe 'authentication' do
    it 'rejects requests without a token' do
      get "/treatment/current/#{patient.id}"

      expect(response).to have_http_status(:unauthorized)
    end

    it 'rejects malformed or incorrectly signed tokens' do
      get "/treatment/current/#{patient.id}",
          headers: { 'Authorization' => 'Bearer not-a-valid-token' }

      expect(response).to have_http_status(:unauthorized)
    end
  end

  describe 'treatment access' do
    it 'allows a patient to read their own current treatment' do
      get "/treatment/current/#{patient.id}", headers: auth_header(patient)

      expect(response).to have_http_status(:ok)
    end

    it 'denies another patient access to the patient current treatment' do
      get "/treatment/current/#{patient.id}", headers: auth_header(outsider_patient)

      expect(response).to have_http_status(:forbidden)
    end

    it 'denies an unlinked physician access to the patient current treatment' do
      get "/treatment/current/#{patient.id}", headers: auth_header(outsider_physician)

      expect(response).to have_http_status(:forbidden)
    end

    it 'allows a physician linked to the patient to read current treatment' do
      PhysicianPatient.create!(physician: physician, patient: patient)

      get "/treatment/current/#{patient.id}", headers: auth_header(physician)

      expect(response).to have_http_status(:ok)
    end

    it 'denies another patient access to treatment history' do
      get "/treatment/history/#{patient.id}", headers: auth_header(outsider_patient)

      expect(response).to have_http_status(:forbidden)
    end
  end

  describe 'prescription access' do
    let!(:prescription) do
      create(:prescription, patient: patient, physician: physician)
    end

    it 'allows the patient to read their own prescription' do
      get "/prescriptions/#{prescription.id}", headers: auth_header(patient)

      expect(response).to have_http_status(:ok)
    end

    it 'denies an unrelated user access to the prescription' do
      get "/prescriptions/#{prescription.id}", headers: auth_header(outsider_patient)

      expect(response).to have_http_status(:forbidden)
    end
  end

  describe 'prescription creation' do
    it 'does not create a prescription for a user who is neither its patient nor physician' do
      medication = create(:medication)
      params = {
        prescription: {
          patient_id: patient.id,
          physician_id: physician.id,
          medication_id: medication.id,
          quantity: 1,
          time: '08:00'
        }
      }

      expect do
        post '/prescriptions', params: params, as: :json, headers: auth_header(outsider_patient)
      end.not_to change(Prescription, :count)

      expect(response).to have_http_status(:unprocessable_entity)
    end
  end
end
