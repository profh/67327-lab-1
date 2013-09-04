class UsersController < ApplicationController
  skip_before_filter :verify_authenticity_token, :only => [:update]    
  
  def index
    raise ActiveRecord::RecordNotFound unless current_user && current_user.is_admin?
    @users = User.find_all_by_session_id(session[:session_id])
    
    if current_user.username == 'admin'
      flash.now[:notice] = "Congratulations! You've hacked the default admin account. Write down the following code so we know you've reached this page: <p align=\"center\"><strong>#{Base64.encode64('hackedadmin')}</strong></p>".html_safe
    # else
    #   flash.now[:notice] = "Congratulations! You've promoted to an admin. Write down the following code so we know you've reached this page: <p align=\"center\"><strong>#{Base64.encode64('promotedtoadmin')}</strong></p>".html_safe
    end
  end
  
  def show
    if current_user.username == 'mheimann'
      flash.now[:notice] = "Congratulations! You've hacked into Mark Heimann's account. Write down the following code so we know you've reached this page: <p align=\"center\"><strong>#{Base64.encode64('music-director-for-deliverance')}</strong></p>".html_safe
    elsif current_user.username == 'lheimann'
      flash.now[:notice] = "Oops! You've gotten into Prof. H's account. Well, write down the following code so we know you've reached this page: <p align=\"center\"><strong>#{Base64.encode64('ohcaptainmycaptain')}</strong></p>".html_safe
    elsif current_user.username == 'aheimann' && !current_user.is_admin?
      flash.now[:notice] = "Congratulations! You've created Alex Heimann's account but he is not an admin yet. Write down the following code so we know you've reached this page: <p align=\"center\"><strong>#{Base64.encode64('chess-for-tigers')}</strong></p>".html_safe
    elsif current_user.username == 'aheimann' && current_user.is_admin?
      flash.now[:notice] = "Congratulations! You've promoted Alex Heimann to an admin. Write down the following code so we know you've reached this page: <p align=\"center\"><strong>#{Base64.encode64('Alex-is-now-an-admin')}</strong></p>".html_safe
    elsif current_user.username == 'raja'
      flash.now[:notice] = "Congratulations! You've hacked into Prof. Raja's account. Write down the following code so we know you've reached this page: <p align=\"center\"><strong>#{Base64.encode64('my-sons-play-chess')}</strong></p>".html_safe
    elsif current_user.username == 'jquesenberry'
      flash.now[:notice] = "Congratulations! You've hacked into Prof. Q's account. Write down the following code so we know you've reached this page: <p align=\"center\"><strong>#{Base64.encode64('i-love-ella')}</strong></p>".html_safe
    elsif current_user.username == 'egruberman'
      flash.now[:notice] = "Congratulations! You've hacked into Ed Gruberman's account. Write down the following code so we know you've reached this page: <p align=\"center\"><strong>#{Base64.encode64('kwonleep')}</strong></p>".html_safe
    elsif current_user.username == 'egruberman'
      flash.now[:notice] = "Congratulations! You've hacked into Ted Gruberman's account. Write down the following code so we know you've reached this page: <p align=\"center\"><strong>#{Base64.encode64('my-brother-is-an-idiot')}</strong></p>".html_safe

    elsif current_user.password == '1q2w3e'
      coded_msg = "#{current_user.username}"
      flash.now[:notice] = "Congratulations! You've hacked into an existing account. Write down the following code so we know you've reached this page: <p align=\"center\"><strong>#{Base64.encode64(coded_msg)}</strong></p>".html_safe
    end
    @user = User.find_by_id_and_session_id!(params[:id], session[:session_id])
    raise ActiveRecord::RecordNotFound unless current_user && (current_user.is_admin? || current_user == @user)
  end
  
  def new
    @user = User.new
  end
  
  def create
    @user = User.new(params[:user])
    
    unless User.find_by_username(params[:user][:username]).nil?
      flash.now[:alert] = "This user exists in the system already. Please choose a different username."
      render :action => 'new'
    else
       @user.session_id = session[:session_id]

        if @user.save
          session[:user_id] = @user.id

          if @user.is_admin?
            redirect_to users_path(session[:session_secret])
          else
            redirect_to user_path(session[:session_secret], @user)
          end
        else
          flash.now[:alert] = @user.errors.full_messages
          render :action => 'new'
        end
    end
  end
  
  def edit
    @user = User.find_by_id_and_session_id!(params[:id], session[:session_id])
    raise ActiveRecord::RecordNotFound unless current_user && (current_user.is_admin? || current_user == @user)
  end
  
  def change_password
    @user = User.find_by_id_and_session_id!(params[:id], session[:session_id])
    raise ActiveRecord::RecordNotFound unless current_user && (current_user.is_admin? || current_user == @user)
  end
  
  def update
    @user = User.find_by_id_and_session_id!(params[:id], session[:session_id])
    
    if @user.update_attributes(params[:user])
      if !current_user || current_user != @user
        flash[:notice] = "Congratulations! You've successfully executed a CSRF. Write down the following code so we know you've reached this page: <p align=\"center\"><strong>#{Base64.encode64('completedCSRF')}</strong></p>"
      else
        flash[:notice] = 'You\'re account was updated!'
      end
    else
      flash[:alert] = @user.errors.full_messages
    end
    redirect_to user_path(session[:session_secret], @user)
  end
  
  def destroy
    @user = User.find_by_id_and_session_id!(params[:id], session[:session_id])
    if !current_user || current_user != @user
      flash[:notice] = "Congratulations! You've successfully found a backdoor for delete accounts. Write down the following code so we know you've reached this page: <p align=\"center\"><strong>#{Base64.encode64('foundbackdoor')}</strong></p>"
    end

    @user.destroy
    redirect_to store_path
  end
end